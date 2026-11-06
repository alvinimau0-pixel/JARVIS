from __future__ import annotations

import argparse
import asyncio
import logging
import signal
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse

from jarvis import __version__
from jarvis.api.routes import router
from jarvis.api.security import AuthMiddleware, RateLimitMiddleware
from jarvis.app_state import Services
from jarvis.core.config import Settings, get_settings
from jarvis.core.logging import configure_logging
from jarvis.core.redaction import register_secret
from jarvis.core.watchdog import watch_parent
from jarvis.db.session import make_engine, make_sessionmaker
from jarvis.events.bus import EventBus
from jarvis.exec.allowlist import Allowlist, default_allowlist
from jarvis.exec.runner import ProcessRegistry
from jarvis.security.emergency import EmergencyLatch
from jarvis.security.policy import PolicyEngine
from jarvis.tasks.service import ActionService

log = logging.getLogger("jarvis")
BACKEND_ROOT = Path(__file__).resolve().parent.parent


def migration_head() -> str:
    cfg = Config(str(BACKEND_ROOT / "alembic.ini"))
    head = ScriptDirectory.from_config(cfg).get_current_head()
    assert head is not None
    return head


def create_app(settings: Settings | None = None, allowlist: Allowlist | None = None) -> FastAPI:
    settings = settings or get_settings()
    token = settings.session_token.get_secret_value()
    register_secret(token)
    register_secret(settings.database_url.get_secret_value())

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = make_engine(settings.database_url.get_secret_value())
        maker = make_sessionmaker(engine)
        bus = EventBus(maker)
        latch = EmergencyLatch(maker)
        await latch.load()
        registry = ProcessRegistry()
        policy = PolicyEngine(
            allowlist=allowlist or default_allowlist(),
            workspaces=settings.workspaces,
            default_timeout_s=settings.exec_default_timeout_seconds,
            max_timeout_s=settings.exec_max_timeout_seconds,
        )
        actions = ActionService(
            maker=maker,
            bus=bus,
            policy=policy,
            registry=registry,
            latch=latch,
            approval_ttl_seconds=settings.approval_ttl_seconds,
            output_limit=settings.exec_output_limit_bytes,
            max_concurrent_jobs=settings.exec_max_concurrent_jobs,
        )
        app.state.services = Services(
            settings, engine, maker, bus, policy, registry, latch, actions, migration_head()
        )
        await actions.recover_after_restart()
        watchdog: asyncio.Task[None] | None = None
        if settings.parent_pid:

            async def on_parent_gone() -> None:
                await actions.shutdown()  # kill controlled children first
                signal.raise_signal(signal.SIGINT)  # graceful uvicorn shutdown

            watchdog = asyncio.create_task(watch_parent(settings.parent_pid, on_parent_gone))
        log.info("JARVIS backend %s ready on %s:%s", __version__, settings.host, settings.port)
        try:
            yield
        finally:
            if watchdog is not None:
                watchdog.cancel()
            await actions.shutdown()
            await engine.dispose()

    app = FastAPI(
        title="JARVIS OS API",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,  # contracts are exported offline; not served at runtime
    )
    app.include_router(router)

    # Order: outermost first after reversal -> CORS, then auth, then rate limit.
    app.add_middleware(RateLimitMiddleware, per_minute=settings.rate_limit_per_minute)
    app.add_middleware(AuthMiddleware, token=token, allowed_origins=settings.allowed_origins)
    # DNS-rebinding defence: only loopback Host headers are accepted.
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "[::1]"])
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["authorization", "content-type"],
        allow_credentials=False,
    )

    @app.exception_handler(HTTPException)
    async def http_error(_: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            {"error": {"code": f"http_{exc.status_code}", "message": str(exc.detail)}},
            status_code=exc.status_code,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        first = exc.errors()[0] if exc.errors() else {}
        loc = ".".join(str(x) for x in first.get("loc", ()))
        return JSONResponse(
            {"error": {"code": "invalid_request", "message": f"{loc}: {first.get('msg', '')}"}},
            status_code=422,
        )

    return app


def _secrets_cli(argv: list[str]) -> int:
    """`jarvis-backend secrets set|delete|status NAME`: values are typed, never passed as args."""
    import getpass

    from jarvis.secrets.store import KNOWN_SECRETS, KeyringStore

    parser = argparse.ArgumentParser(prog="jarvis-backend secrets")
    parser.add_argument("op", choices=["set", "delete", "status"])
    parser.add_argument("name", choices=KNOWN_SECRETS)
    args = parser.parse_args(argv)
    store = KeyringStore()
    if args.op == "set":
        value = getpass.getpass(f"{args.name}: ")
        if not value:
            print("empty value; nothing stored")
            return 1
        store.set(args.name, value)
        print(f"{args.name} stored in the OS credential store")
    elif args.op == "delete":
        store.delete(args.name)
        print(f"{args.name} deleted")
    else:
        print(f"{args.name}: {'present' if store.get(args.name) else 'absent'}")
    return 0


def run() -> None:
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "secrets":
        raise SystemExit(_secrets_cli(sys.argv[2:]))
    parser = argparse.ArgumentParser(description="JARVIS OS backend")
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args()
    configure_logging()
    settings = get_settings()
    if args.port:
        settings.port = args.port
    import uvicorn

    uvicorn.run(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        log_config=None,
        access_log=False,  # requests are audited by JARVIS itself; avoids logging URLs
        ws="websockets",
    )


if __name__ == "__main__":
    run()
