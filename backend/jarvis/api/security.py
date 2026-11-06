"""Request authentication, origin enforcement and rate limiting.

The desktop shell generates a random session token per launch and passes it to the webview
over Tauri IPC. Every HTTP request must carry ``Authorization: Bearer <token>``; WebSocket
clients send it as the subprotocol ``auth.<token>`` (browsers cannot set WS headers).
"""

from __future__ import annotations

import hmac
import time
from collections import defaultdict, deque

from fastapi import Request, WebSocket
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from jarvis.security.principal import Principal

WS_PROTOCOL = "jarvis.v1"
WS_AUTH_PREFIX = "auth."
PUBLIC_PATHS = frozenset({"/api/v1/health/live"})


def token_matches(presented: str | None, expected: str) -> bool:
    if not presented:
        return False
    return hmac.compare_digest(presented.encode(), expected.encode())


def error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse({"error": {"code": code, "message": message}}, status_code=status)


class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: object, *, token: str, allowed_origins: list[str]) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._token = token
        self._origins = set(allowed_origins)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.scope["type"] != "http":
            return await call_next(request)
        origin = request.headers.get("origin")
        if origin is not None and origin not in self._origins:
            return error(403, "origin_not_allowed", "request origin is not allowed")
        if request.method == "OPTIONS" or request.url.path in PUBLIC_PATHS:
            return await call_next(request)
        if not request.url.path.startswith("/api/"):
            return await call_next(request)
        header = request.headers.get("authorization", "")
        presented = header[7:] if header.lower().startswith("bearer ") else None
        if not token_matches(presented, self._token):
            return error(401, "unauthenticated", "missing or invalid session token")
        request.state.principal = Principal.operator()
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window limit on mutating requests (defence against runaway loops)."""

    def __init__(self, app: object, *, per_minute: int) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._limit = per_minute
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        expensive = request.url.path in {"/api/v1/audit/verify"}
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} or expensive:
            # The emergency stop must never be rate limited.
            if request.url.path != "/api/v1/system/emergency-stop":
                key = request.client.host if request.client else "unknown"
                now = time.monotonic()
                window = self._hits[key]
                while window and now - window[0] > 60:
                    window.popleft()
                if len(window) >= self._limit:
                    return error(429, "rate_limited", "too many requests")
                window.append(now)
        return await call_next(request)


def authenticate_websocket(ws: WebSocket, token: str, allowed_origins: list[str]) -> str | None:
    """Return the protocol to accept with, or None to reject."""
    origin = ws.headers.get("origin")
    if origin is not None and origin not in allowed_origins:
        return None
    offered = [p.strip() for p in ws.headers.get("sec-websocket-protocol", "").split(",")]
    if WS_PROTOCOL not in offered:
        return None
    presented = next(
        (p[len(WS_AUTH_PREFIX) :] for p in offered if p.startswith(WS_AUTH_PREFIX)), None
    )
    if not token_matches(presented, token):
        return None
    return WS_PROTOCOL
