from __future__ import annotations

import os
import secrets
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from jarvis.core.config import Settings
from jarvis.exec.allowlist import Allowlist, default_allowlist
from jarvis.main import create_app
from tests.helpers import pyproc_rule

BACKEND = Path(__file__).resolve().parent.parent
TEST_DB = os.environ.get("JARVIS_TEST_DATABASE_URL")


def sync_url() -> str:
    assert TEST_DB
    return TEST_DB


def alembic(*args: str) -> None:
    env = {**os.environ, "JARVIS_DATABASE_URL": sync_url()}
    subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=BACKEND,
        env=env,
        check=True,
        capture_output=True,
    )


def reset_database() -> None:
    alembic("downgrade", "base")
    alembic("upgrade", "head")


@pytest.fixture(scope="session")
def _migrated() -> None:
    if not TEST_DB:
        pytest.skip("JARVIS_TEST_DATABASE_URL not set")
    reset_database()


@pytest.fixture()
def db(_migrated: None) -> Iterator[Any]:
    engine = create_engine(sync_url())
    yield engine
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM system_state"))
    engine.dispose()


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "proj"
    ws.mkdir()
    subprocess.run(["git", "init", "-q", str(ws)], check=True)
    (ws / "README.md").write_text("hello\n")
    return ws


@pytest.fixture()
def token() -> str:
    return secrets.token_urlsafe(32)


def make_allowlist() -> Allowlist:
    allow = default_allowlist()
    allow.add(pyproc_rule(level=1))
    allow.add(pyproc_rule(level=2, name="pyproc-l2"))
    allow.add(pyproc_rule(level=3, name="pyproc-l3"))
    return allow


@pytest.fixture()
def client(db: Any, workspace: Path, token: str) -> Iterator[TestClient]:
    settings = Settings(
        session_token=token,  # type: ignore[arg-type]
        database_url=sync_url(),  # type: ignore[arg-type]
        workspaces=[workspace],
        rate_limit_per_minute=1000,
    )
    app = create_app(settings, allowlist=make_allowlist())
    with TestClient(app, base_url="http://127.0.0.1") as c:
        c.headers["Authorization"] = f"Bearer {token}"
        yield c


def wait_job(client: TestClient, job_id: str, timeout: float = 15) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = client.get(f"/api/v1/jobs/{job_id}").json()
        if job["status"] not in {"queued", "running"}:
            return job
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not finish: {job}")


def wait_running(client: TestClient, job_id: str, timeout: float = 10) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = client.get(f"/api/v1/jobs/{job_id}").json()
        if job["status"] == "running":
            return job
        time.sleep(0.05)
    raise AssertionError("job never started")


def run_action(client: TestClient, ws: Path, exe: str, args: list[str], **kw: Any) -> Any:
    body = {
        "action": "exec.run",
        "params": {"executable": exe, "args": args, "workspace": ws.name},
        **kw,
    }
    return client.post("/api/v1/actions", json=body)
