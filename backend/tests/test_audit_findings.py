"""Regression tests for the independent security audit (docs/KNOWN_ISSUES.md, AUD-* ids).

Each test reproduces the auditor's scenario and demonstrates it is now blocked.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from jarvis.core.config import Settings
from jarvis.core.redaction import REDACTED, RedactingFilter, redact_text
from jarvis.core.watchdog import pid_alive, watch_parent
from jarvis.exec.allowlist import (
    ArgumentRejected,
    validate_git_push,
    validate_git_read,
    validate_pytest,
)
from jarvis.exec.runner import ProcessRegistry, run_controlled
from tests.conftest import run_action, wait_job, wait_running
from tests.helpers import SPAWN_TREE, pyproc_rule

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX process semantics")


def _alive(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().rsplit(")", 1)[-1].split()[0] != "Z"
    except FileNotFoundError:
        return False


# ---------------------------------------------------------------- AUD-H1 git escapes
@pytest.mark.parametrize(
    "args",
    [
        ["diff", "--no-index", "/etc/passwd", "/dev/null"],
        ["diff", "--ext-d"],  # abbreviation of --ext-diff
        ["diff", "--textc"],  # abbreviation of --textconv
        ["log", "--show-signature"],
        ["show", "--show-signature"],
        ["branch", "new-branch"],
        ["branch", "-f", "main", "HEAD~1"],
        ["branch", "--set-upstream-to=origin/x"],
        ["branch", "--edit-description"],
        ["diff", "../outside.txt"],
        ["log", "--", "/etc/passwd"],
        ["ls-files", "C:\\Windows"],
        ["status", "--output=x"],
    ],
)
def test_aud_h1_git_escapes_rejected(args: list[str]) -> None:
    with pytest.raises(ArgumentRejected):
        validate_git_read(args)


@pytest.mark.parametrize(
    "args",
    [
        ["status", "--porcelain"],
        ["log", "--oneline", "-n", "5"],
        ["log", "--format=%h %an %s", "main..feature"],
        ["diff", "--stat", "HEAD~1", "--", "src/app.py"],
        ["branch", "--show-current"],
        ["rev-parse", "--abbrev-ref", "HEAD"],
    ],
)
def test_aud_h1_legitimate_git_still_works(args: list[str]) -> None:
    validate_git_read(args)


@pytest.mark.parametrize(
    "args", [["origin", "../x"], ["origin", "main.lock"], ["/tmp/repo", "main"]]
)
def test_aud_h1_git_push_operands(args: list[str]) -> None:
    with pytest.raises(ArgumentRejected):
        validate_git_push(args)


def test_aud_h1_no_index_blocked_end_to_end(client: TestClient, workspace: Path) -> None:
    r = run_action(client, workspace, "git", ["diff", "--no-index", "/etc/passwd", "/dev/null"])
    assert r.status_code == 403 and r.json()["error"]["code"] == "not_allowlisted"


# -------------------------------------------------------------- AUD-H2 pytest escapes
@pytest.mark.parametrize(
    "tail",
    [
        ["/tmp/attacker_dir"],
        ["../outside"],
        ["-o", "addopts=-pmod"],
        ["-c", "/abs/x.ini"],
        ["--junitxml=/abs/path.xml"],
        ["--rootdir=/"],
        ["--confcutdir=/"],
        ["--cache-dir=/tmp/x"],
        ["-p", "evil"],
        ["-pevil"],
        ["--pyargs", "os"],
    ],
)
def test_aud_h2_pytest_escapes_rejected(tail: list[str]) -> None:
    with pytest.raises(ArgumentRejected):
        validate_pytest(["-m", "pytest", *tail])


def test_aud_h2_legitimate_pytest_still_works() -> None:
    validate_pytest(["-m", "pytest", "-q", "-x", "tests/test_a.py::test_b", "-k", "a and not b"])


# --------------------------------------------------------------- AUD-H3 start-up race
@posix_only
async def test_aud_h3_abort_after_registration_kills_process(tmp_path: Path) -> None:
    res = await run_controlled(
        rule=pyproc_rule(),
        argv_tail=["-c", SPAWN_TREE],
        cwd=tmp_path,
        timeout_s=30,
        output_limit=1 << 16,
        registry=ProcessRegistry(),
        job_id=uuid.uuid4(),
        should_abort=lambda: True,  # a stop arrived while the process was being created
    )
    assert res.cancelled and res.duration_s < 10


# ------------------------------------------------------- AUD-M2 denials persisted
def _last_audit(client: TestClient) -> dict[str, Any]:
    return client.get("/api/v1/audit", params={"limit": 1}).json()[0]


def test_aud_m2_replayed_approval_denial_is_persisted(client: TestClient, workspace: Path) -> None:
    code = ["-c", "print(1)"]
    appr = run_action(client, workspace, "pyproc-l2", code).json()["approval"]
    client.post(f"/api/v1/approvals/{appr['id']}/approve")
    wait_job(
        client,
        run_action(client, workspace, "pyproc-l2", code, approval_id=appr["id"]).json()["job_id"],
    )
    r = run_action(client, workspace, "pyproc-l2", code, approval_id=appr["id"])
    assert r.status_code == 409
    entry = _last_audit(client)
    assert entry["decision"] == "denied" and entry["details"]["code"] == "approval_already_used"


def test_aud_m2_rejected_decision_is_persisted(client: TestClient, workspace: Path) -> None:
    from jarvis.security.approvals import ApprovalError
    from jarvis.security.principal import Principal

    svc = client.app.state.services  # type: ignore[attr-defined]
    appr = run_action(client, workspace, "pyproc-l2", ["-c", "print(1)"]).json()["approval"]
    with pytest.raises(ApprovalError):
        client.portal.call(
            svc.actions.decide, Principal.agent("codex"), uuid.UUID(appr["id"]), True
        )  # type: ignore[union-attr]
    entry = _last_audit(client)
    assert entry["action"] == "approval.decide" and entry["decision"] == "denied"
    assert entry["actor_kind"] == "agent" and entry["details"]["code"] == "approver_not_human"


# ----------------------------------------------- AUD-M5 latch released only on commit
def test_aud_m5_failed_reset_keeps_execution_blocked(
    client: TestClient, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client.post("/api/v1/system/emergency-stop")
    r = client.post("/api/v1/actions", json={"action": "system.emergency_reset", "params": {}})
    appr_id = r.json()["approval"]["id"]
    client.post(f"/api/v1/approvals/{appr_id}/approve")

    from jarvis.tasks import service as service_mod

    real_append = service_mod.audit.append

    async def failing_append(session: Any, **kw: Any) -> Any:
        if kw.get("action") == "system.emergency_reset":
            raise RuntimeError("simulated DB failure during reset")
        return await real_append(session, **kw)

    monkeypatch.setattr(service_mod.audit, "append", failing_append)
    with pytest.raises(RuntimeError):
        client.post("/api/v1/actions", json={"action": "system.emergency_reset", "params": {},
                                             "approval_id": appr_id})  # fmt: skip
    monkeypatch.setattr(service_mod.audit, "append", real_append)
    assert client.get("/api/v1/system/state").json()["emergency_stop"] is True
    assert run_action(client, workspace, "git", ["status"]).status_code == 423


# ------------------------------------------- emergency stop must not depend on the DB
@posix_only
def test_emergency_stop_kills_even_when_database_is_unavailable(
    client: TestClient, workspace: Path
) -> None:
    svc = client.app.state.services  # type: ignore[attr-defined]
    job_id = run_action(client, workspace, "pyproc", ["-c", SPAWN_TREE]).json()["job_id"]
    leader = wait_running(client, job_id)["pid"]
    real_maker = svc.actions.maker

    def broken_maker() -> Any:
        raise ConnectionError("database unavailable")

    svc.actions.maker = broken_maker
    try:
        report = client.post("/api/v1/system/emergency-stop").json()
    finally:
        svc.actions.maker = real_maker
    assert report["latched"] is True and report["persisted"] is False
    assert any(p["pid"] == leader and p["stopped"] for p in report["processes"])
    assert not _alive(leader)


# ------------------------------------------------------- AUD-M6 concurrency limit
def test_aud_m6_concurrent_job_limit(client: TestClient, workspace: Path) -> None:
    svc = client.app.state.services  # type: ignore[attr-defined]
    svc.actions.max_concurrent_jobs = 1
    first = run_action(client, workspace, "pyproc", ["-c", "import time; time.sleep(30)"]).json()
    wait_running(client, first["job_id"])
    r = run_action(client, workspace, "git", ["status"])
    assert r.status_code == 429 and r.json()["error"]["code"] == "concurrency_limit"
    client.post(f"/api/v1/jobs/{first['job_id']}/cancel")
    wait_job(client, first["job_id"])


# ------------------------------------------------- AUD-L4 approvals expire on stop
def test_aud_l4_emergency_stop_expires_outstanding_approvals(
    client: TestClient, workspace: Path
) -> None:
    pending = run_action(client, workspace, "pyproc-l2", ["-c", "print(1)"]).json()["approval"]
    approved = run_action(client, workspace, "pyproc-l2", ["-c", "print(2)"]).json()["approval"]
    client.post(f"/api/v1/approvals/{approved['id']}/approve")
    client.post("/api/v1/system/emergency-stop")
    by_id = {a["id"]: a for a in client.get("/api/v1/approvals").json()}
    assert by_id[pending["id"]]["status"] == "expired"
    assert by_id[approved["id"]]["status"] == "expired"


# -------------------------------------------------------- AUD-L5 DNS rebinding
@pytest.mark.parametrize("host", ["evil.example", "attacker.test:8765", "192.168.1.5"])
def test_aud_l5_non_loopback_host_header_rejected(client: TestClient, host: str) -> None:
    assert client.get("/api/v1/health", headers={"Host": host}).status_code == 400


# ------------------------------------------------- AUD-L6 workspace name collisions
def test_aud_l6_duplicate_workspace_names_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(session_token="t" * 43, database_url="postgresql://x",  # type: ignore[arg-type]
                 workspaces=[Path("/a/proj"), Path("/b/proj")])  # fmt: skip


# ------------------------------------------------------------ AUD-L1 redaction
@pytest.mark.parametrize(
    "secret",
    [
        "sk_live_abcdefghijklmnop1234",
        "AIzaSyA1234567890abcdefghijklmnopqrstuv",
        "ASIAABCDEFGHIJKLMNOP",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    ],
)
def test_aud_l1_more_secret_formats_redacted(secret: str) -> None:
    assert secret not in redact_text(f"x {secret} y")


def test_aud_l1_cli_flags_and_url_credentials_redacted() -> None:
    out = redact_text("run --password hunter2 then https://bob:pa55w0rd@example.com/x")
    assert "hunter2" not in out and "pa55w0rd" not in out and REDACTED in out


def test_aud_l1_tracebacks_are_redacted(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("jarvis.test.tb")
    logger.addFilter(RedactingFilter())
    with caplog.at_level(logging.ERROR, logger="jarvis.test.tb"):
        try:
            raise ValueError("bad key sk-ant-api03-tracebackleak000000")
        except ValueError:
            logger.exception("provider call failed")
    assert "tracebackleak" not in caplog.text and "provider call failed" in caplog.text


# ------------------------------------------------------- AUD-M4 parent watchdog
def test_aud_m4_pid_alive() -> None:
    import os

    assert pid_alive(os.getpid())
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    assert not pid_alive(p.pid)


async def test_aud_m4_watchdog_fires_when_parent_dies() -> None:
    parent = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(0.3)"])
    fired = asyncio.Event()

    async def on_gone() -> None:
        fired.set()

    task = asyncio.create_task(watch_parent(parent.pid, on_gone, interval_s=0.1))
    started = time.monotonic()
    await asyncio.wait_for(fired.wait(), timeout=5)
    parent.wait()
    assert time.monotonic() - started < 5
    await task


def test_aud_l5_websocket_with_foreign_host_rejected(client: TestClient, token: str) -> None:
    from starlette.testclient import WebSocketDenialResponse

    with pytest.raises(WebSocketDenialResponse):
        with client.websocket_connect(
            "ws://testserver/api/v1/ws", subprotocols=["jarvis.v1", f"auth.{token}"]
        ):
            pass
