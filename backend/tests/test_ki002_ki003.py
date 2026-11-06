"""KI-003 (agent vs human separation) and KI-002 (audit log tamper resistance).

KI-003: agents authenticate with their own revocable credentials, reach only a small set of
routes, can never decide approvals or reset the emergency stop, and can spend only approvals
they requested themselves.

KI-002: the audit chain is keyed (HMAC), the runtime database role cannot alter or unprotect
audit rows, and the chain head is anchored outside the database so tail truncation is caught.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, make_url, text

from jarvis.audit import log as audit_log
from jarvis.audit.anchor import ANCHOR_FILENAME
from jarvis.core.config import AUDIT_KEY_SECRET, load_settings
from jarvis.core.redaction import REDACTED, redact_text
from jarvis.main import create_app
from jarvis.secrets.store import MemoryStore
from jarvis.security.agents import AgentCredentials, agent_may_call
from jarvis.security.hashing import canonical_json
from tests.conftest import (
    AUDIT_KEY,
    make_allowlist,
    make_settings,
    reset_database,
    run_action,
    sync_url,
    wait_job,
)

L2_CODE = ["-c", "print('l2 ran')"]


def issue(client: TestClient, agent_id: str) -> str:
    r = client.post("/api/v1/agents/credentials", json={"agent_id": agent_id})
    assert r.status_code == 201, r.text
    return str(r.json()["token"])


def as_agent(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def last_audit(client: TestClient) -> dict[str, Any]:
    return client.get("/api/v1/audit", params={"limit": 1}).json()[0]  # type: ignore[no-any-return]


# =========================================================== KI-003: credentials
def test_agent_can_submit_actions_and_is_audited_as_agent(
    client: TestClient, workspace: Path
) -> None:
    tok = issue(client, "codex")
    baseline = last_audit(client)["id"]
    r = client.post(
        "/api/v1/actions",
        headers=as_agent(tok),
        json={
            "action": "exec.run",
            "params": {"executable": "git", "args": ["status"], "workspace": workspace.name},
        },
    )
    assert r.status_code == 202, r.text
    job_id = r.json()["job_id"]
    assert client.get(f"/api/v1/jobs/{job_id}", headers=as_agent(tok)).status_code == 200
    wait_job(client, job_id)
    entries = client.get("/api/v1/audit", params={"limit": 20}).json()
    mine = [e for e in entries if e["action"] == "exec.run" and e["id"] > baseline]
    assert mine and all(e["actor_kind"] == "agent" and e["actor_id"] == "codex" for e in mine)


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/api/v1/approvals/00000000-0000-0000-0000-000000000000/approve"),
        ("POST", "/api/v1/approvals/00000000-0000-0000-0000-000000000000/deny"),
        ("GET", "/api/v1/approvals"),
        ("POST", "/api/v1/system/emergency-stop"),
        ("GET", "/api/v1/audit"),
        ("GET", "/api/v1/audit/verify"),
        ("GET", "/api/v1/events"),
        ("GET", "/api/v1/tasks"),
        ("GET", "/api/v1/agents/credentials"),
        ("POST", "/api/v1/agents/credentials"),
        ("POST", "/api/v1/agents/credentials/codex/revoke"),
    ],
)
def test_agent_is_kept_off_human_routes(client: TestClient, method: str, path: str) -> None:
    tok = issue(client, "codex")
    r = client.request(method, path, headers=as_agent(tok), json={"agent_id": "evil"})
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "agent_forbidden"


def test_agent_token_cannot_open_the_event_websocket(client: TestClient) -> None:
    from starlette.websockets import WebSocketDisconnect

    tok = issue(client, "codex")
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(
            "ws://127.0.0.1/api/v1/ws", subprotocols=["jarvis.v1", f"auth.{tok}"]
        ) as ws:
            ws.receive_json()
    assert exc.value.code == 4401


def test_agent_cannot_approve_its_own_request(client: TestClient, workspace: Path) -> None:
    tok = issue(client, "claude-code")
    r = client.post(
        "/api/v1/actions",
        headers=as_agent(tok),
        json={
            "action": "exec.run",
            "params": {"executable": "pyproc-l2", "args": L2_CODE, "workspace": workspace.name},
        },
    )
    assert r.status_code == 202 and r.json()["status"] == "approval_required"
    appr = r.json()["approval"]
    assert appr["requester_kind"] == "agent" and appr["requester_id"] == "claude-code"
    r = client.post(f"/api/v1/approvals/{appr['id']}/approve", headers=as_agent(tok))
    assert r.status_code == 403
    pending = client.get("/api/v1/approvals", params={"status": "pending"}).json()
    assert appr["id"] in {a["id"] for a in pending}


def test_service_layer_also_rejects_agent_approvals(client: TestClient, workspace: Path) -> None:
    """Defence in depth: even if a route check were bypassed, decide() refuses agents."""
    import uuid

    from jarvis.security.approvals import ApprovalError
    from jarvis.security.principal import Principal

    svc = client.app.state.services  # type: ignore[attr-defined]
    appr = run_action(client, workspace, "pyproc-l2", L2_CODE).json()["approval"]
    with pytest.raises(ApprovalError):
        client.portal.call(  # type: ignore[union-attr]
            svc.actions.decide, Principal.agent("claude-code"), uuid.UUID(appr["id"]), True
        )


def test_approval_can_only_be_spent_by_its_requester(client: TestClient, workspace: Path) -> None:
    alice, bob = issue(client, "alice"), issue(client, "bob")
    body = {
        "action": "exec.run",
        "params": {"executable": "pyproc-l2", "args": L2_CODE, "workspace": workspace.name},
    }
    appr = client.post("/api/v1/actions", headers=as_agent(alice), json=body).json()["approval"]
    assert client.post(f"/api/v1/approvals/{appr['id']}/approve").status_code == 200

    spend = {**body, "approval_id": appr["id"]}
    r = client.post("/api/v1/actions", headers=as_agent(bob), json=spend)
    assert r.status_code == 403 and r.json()["error"]["code"] == "approval_requester_mismatch"
    r = client.post("/api/v1/actions", json=spend)  # nor the operator on the agent's behalf
    assert r.status_code == 403 and r.json()["error"]["code"] == "approval_requester_mismatch"

    r = client.post("/api/v1/actions", headers=as_agent(alice), json=spend)
    assert r.status_code == 202, r.text
    assert wait_job(client, r.json()["job_id"])["status"] == "completed"


def test_agent_cannot_reset_the_emergency_stop(client: TestClient) -> None:
    client.post("/api/v1/system/emergency-stop")
    # Credentials cannot be issued while stopped, and the stop revoked any earlier ones.
    r = client.post("/api/v1/agents/credentials", json={"agent_id": "codex"})
    assert r.status_code == 423
    svc = client.app.state.services  # type: ignore[attr-defined]
    _, tok = svc.actions.agents.issue("codex")  # simulate a credential that slipped through
    r = client.post(
        "/api/v1/actions",
        headers=as_agent(tok),
        json={"action": "system.emergency_reset", "params": {}},
    )
    assert r.status_code == 403 and r.json()["error"]["code"] == "agent_cannot_modify_policy"


def test_emergency_stop_revokes_every_agent_credential(client: TestClient) -> None:
    toks = [issue(client, "codex"), issue(client, "claude-code")]
    report = client.post("/api/v1/system/emergency-stop").json()
    assert report["agent_credentials_revoked"] == 2
    for tok in toks:
        assert client.get("/api/v1/catalog", headers=as_agent(tok)).status_code == 401
    entry = next(
        e
        for e in client.get("/api/v1/audit", params={"limit": 10}).json()
        if e["action"] == "system.emergency_stop"
    )
    assert entry["details"]["agents_revoked"] == 2


def test_revoked_credential_stops_working_and_is_audited(client: TestClient) -> None:
    tok = issue(client, "codex")
    assert client.get("/api/v1/catalog", headers=as_agent(tok)).status_code == 200
    listed = client.get("/api/v1/agents/credentials").json()
    assert [c["agent_id"] for c in listed] == ["codex"] and "token" not in listed[0]
    r = client.post("/api/v1/agents/credentials/codex/revoke")
    assert r.json() == {"agent_id": "codex", "revoked": True}
    assert client.get("/api/v1/catalog", headers=as_agent(tok)).status_code == 401
    entries = client.get("/api/v1/audit", params={"limit": 5}).json()
    assert entries[0]["action"] == "agent.credential_revoke"
    issued = next(e for e in entries if e["action"] == "agent.credential_issue")
    assert tok not in json.dumps(entries) and issued["target"] == "codex"


@pytest.mark.parametrize("agent_id", ["operator", "jarvis", "Upper", "has space", "", "x" * 65])
def test_invalid_or_reserved_agent_ids_rejected(client: TestClient, agent_id: str) -> None:
    r = client.post("/api/v1/agents/credentials", json={"agent_id": agent_id})
    assert r.status_code == 422


def test_duplicate_active_agent_rejected(client: TestClient) -> None:
    issue(client, "codex")
    r = client.post("/api/v1/agents/credentials", json={"agent_id": "codex"})
    assert r.status_code == 409 and r.json()["error"]["code"] == "agent_already_active"


def test_agent_credentials_unit() -> None:
    creds = AgentCredentials()
    cred, tok = creds.issue("codex")
    assert tok.startswith("jat_") and len(tok) > 40 and tok not in repr(cred)
    who = creds.authenticate(tok)
    assert who is not None and not who.is_human and who.id == "codex"
    for wrong in (None, "", "jat_", tok[:-1] + ("A" if tok[-1] != "A" else "B"), tok[4:]):
        assert creds.authenticate(wrong) is None
    assert redact_text(f"token={tok} x {tok}").count(REDACTED) >= 1 and tok not in redact_text(tok)
    assert not agent_may_call("POST", "/api/v1/approvals/x/approve")
    assert agent_may_call("POST", "/api/v1/actions")
    assert not agent_may_call("GET", "/api/v1/actions")


# ============================================================ KI-002: keyed chain
def test_chain_is_keyed(client: TestClient, db: Any) -> None:
    from datetime import UTC

    client.post("/api/v1/actions", json={"action": "nope"})
    with db.begin() as conn:
        row = conn.execute(text("SELECT * FROM audit_log ORDER BY id DESC LIMIT 1")).one()
    fields = {
        "prev_hash": row.prev_hash,
        "ts": row.ts,
        "actor_kind": row.actor_kind,
        "actor_id": row.actor_id,
        "action": row.action,
        "target": row.target,
        "level": row.level,
        "decision": row.decision,
        "details": row.details,
    }
    assert audit_log.compute_hash(**fields) == row.hash  # recomputable with the key...
    body = {k: v for k, v in fields.items() if k not in {"prev_hash", "ts"}}
    body |= {"prev": row.prev_hash, "ts": row.ts.astimezone(UTC).isoformat()}
    plain = hashlib.sha256(canonical_json(body).encode()).hexdigest()
    assert row.hash != plain  # ...but not as a plain hash by someone without it


def test_forged_entry_without_the_key_is_detected(client: TestClient, db: Any) -> None:
    """Someone with full DB access appends a well-formed, correctly linked entry."""
    client.post("/api/v1/actions", json={"action": "nope"})
    head = last_audit(client)
    body = {
        "prev": head["hash"],
        "ts": "2026-11-06T00:00:00+00:00",
        "actor_kind": "human",
        "actor_id": "operator",
        "action": "approval.decide",
        "target": "forged",
        "level": 3,
        "decision": "approved",
        "details": {},
    }
    forged = hashlib.sha256(canonical_json(body).encode()).hexdigest()
    try:
        with db.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO audit_log (ts, actor_kind, actor_id, action, target, level, "
                    "decision, details, prev_hash, hash) VALUES ('2026-11-06T00:00:00+00:00', "
                    "'human', 'operator', 'approval.decide', 'forged', 3, 'approved', '{}', "
                    ":prev, :hash)"
                ),
                {"prev": head["hash"], "hash": forged},
            )
        result = client.get("/api/v1/audit/verify").json()
        assert result["ok"] is False and "keyed hash" in result["detail"]
    finally:
        reset_database()


def test_wrong_key_fails_verification(client: TestClient) -> None:
    client.post("/api/v1/actions", json={"action": "nope"})
    assert client.get("/api/v1/audit/verify").json()["ok"] is True
    try:
        audit_log.set_key("a-completely-different-audit-key-0000000000")
        result = client.get("/api/v1/audit/verify").json()
        assert result["ok"] is False and result["first_bad_id"] is not None
    finally:
        audit_log.set_key(AUDIT_KEY)


def test_unconfigured_key_fails_closed() -> None:
    saved = audit_log._key
    audit_log._key = None
    try:
        with pytest.raises(audit_log.AuditKeyMissing):
            audit_log._require_key()
    finally:
        audit_log._key = saved
    with pytest.raises(ValueError):
        audit_log.set_key("too-short")


def test_backend_refuses_to_start_without_an_audit_key(workspace: Path, data_dir: Path) -> None:
    settings = make_settings("t" * 43, workspace, data_dir, audit_key=None)
    with pytest.raises(RuntimeError, match="No audit key"):
        create_app(settings)


# ------------------------------------------------------------ key storage
def test_audit_key_is_generated_once_in_the_credential_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("JARVIS_SESSION_TOKEN", "t" * 43)
    monkeypatch.setenv("JARVIS_DATABASE_URL", "postgresql+psycopg://x@127.0.0.1/x")
    monkeypatch.delenv("JARVIS_AUDIT_KEY", raising=False)
    store = MemoryStore()
    first = load_settings(store).audit_key
    assert first is not None and store.get(AUDIT_KEY_SECRET) == first.get_secret_value()
    second = load_settings(store).audit_key
    assert second is not None and second.get_secret_value() == first.get_secret_value()
    assert first.get_secret_value() not in repr(load_settings(store))


def test_audit_key_from_environment_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JARVIS_SESSION_TOKEN", "t" * 43)
    monkeypatch.setenv("JARVIS_DATABASE_URL", "postgresql+psycopg://x@127.0.0.1/x")
    monkeypatch.setenv("JARVIS_AUDIT_KEY", "e" * 40)
    store = MemoryStore()
    key = load_settings(store).audit_key
    assert key is not None and key.get_secret_value() == "e" * 40
    assert store.get(AUDIT_KEY_SECRET) is None


def test_no_credential_store_means_no_key(monkeypatch: pytest.MonkeyPatch) -> None:
    class Broken(MemoryStore):
        def set(self, name: str, value: str) -> None:
            raise RuntimeError("no secret service")

    monkeypatch.setenv("JARVIS_SESSION_TOKEN", "t" * 43)
    monkeypatch.setenv("JARVIS_DATABASE_URL", "postgresql+psycopg://x@127.0.0.1/x")
    monkeypatch.delenv("JARVIS_AUDIT_KEY", raising=False)
    assert load_settings(Broken()).audit_key is None  # and create_app then refuses to start


# ================================================================ KI-002: anchor
def test_head_is_anchored_outside_the_database(client: TestClient, data_dir: Path) -> None:
    client.post("/api/v1/actions", json={"action": "nope"})
    svc = client.app.state.services  # type: ignore[attr-defined]

    async def record() -> Any:
        async with svc.maker() as session:
            return await svc.anchor.record(session)

    head = client.portal.call(record)  # type: ignore[union-attr]
    assert head is not None and head.id == last_audit(client)["id"]
    lines = (data_dir / ANCHOR_FILENAME).read_text().splitlines()
    assert json.loads(lines[-1])["hash"] == head.hash
    again = client.portal.call(record)  # type: ignore[union-attr]
    assert again == head and len((data_dir / ANCHOR_FILENAME).read_text().splitlines()) == len(
        lines
    )  # unchanged head: nothing appended
    result = client.get("/api/v1/audit/verify").json()
    assert result["ok"] is True and result["anchored_id"] == head.id


def _write_anchor(data_dir: Path, entry_id: int, entry_hash: str) -> None:
    with (data_dir / ANCHOR_FILENAME).open("a") as fh:
        fh.write(json.dumps({"id": entry_id, "hash": entry_hash, "ts": "x"}) + "\n")


def test_truncated_tail_is_detected(client: TestClient, data_dir: Path) -> None:
    client.post("/api/v1/actions", json={"action": "nope"})
    head = last_audit(client)
    # The anchor saw an entry beyond the current head: entries were removed from the end.
    _write_anchor(data_dir, head["id"] + 5, "f" * 64)
    result = client.get("/api/v1/audit/verify").json()
    assert result["ok"] is False and "removed" in result["detail"]


def test_rewritten_anchored_entry_is_detected(client: TestClient, data_dir: Path) -> None:
    client.post("/api/v1/actions", json={"action": "nope"})
    head = last_audit(client)
    _write_anchor(data_dir, head["id"], "0" * 64)
    result = client.get("/api/v1/audit/verify").json()
    assert result["ok"] is False and "rewritten" in result["detail"]


def test_corrupt_anchor_file_is_reported(client: TestClient, data_dir: Path) -> None:
    client.post("/api/v1/actions", json={"action": "nope"})
    (data_dir / ANCHOR_FILENAME).write_text("not json\n")
    result = client.get("/api/v1/audit/verify").json()
    assert result["ok"] is False and "unreadable" in result["detail"]


# ======================================================= KI-002: restricted role
APP_LOGIN = "jarvis_runtime_test"


@pytest.fixture()
def runtime_url(db: Any) -> Iterator[str]:
    """A login role that is a member of jarvis_app, as an install would create it."""
    with db.begin() as conn:
        conn.execute(
            text(
                f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_LOGIN}')"
                f" THEN CREATE ROLE {APP_LOGIN} LOGIN IN ROLE jarvis_app; END IF; END $$;"
            )
        )
    yield (
        make_url(sync_url())
        .set(username=APP_LOGIN, password=None)
        .render_as_string(hide_password=False)
    )


@pytest.mark.parametrize(
    ("stmt", "expected"),
    [
        ("UPDATE audit_log SET decision = 'allowed'", "permission denied"),
        ("DELETE FROM audit_log", "permission denied"),
        ("TRUNCATE audit_log", "permission denied"),
        ("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update_delete", "must be owner"),
        ("DROP TRIGGER audit_log_no_update_delete ON audit_log", "must be owner"),
        ("DROP TABLE audit_log", "must be owner"),
        ("ALTER TABLE audit_log OWNER TO jarvis_runtime_test", "must be owner"),
    ],
)
def test_runtime_role_cannot_alter_or_unprotect_the_audit_log(
    client: TestClient, runtime_url: str, stmt: str, expected: str
) -> None:
    client.post("/api/v1/actions", json={"action": "nope"})
    engine = create_engine(runtime_url)
    try:
        with pytest.raises(Exception, match=expected):
            with engine.begin() as conn:
                conn.execute(text(stmt))
        with engine.begin() as conn:  # reading is allowed
            assert conn.execute(text("SELECT count(*) FROM audit_log")).scalar_one() > 0
    finally:
        engine.dispose()


def test_full_journey_works_as_the_runtime_role(
    runtime_url: str, workspace: Path, token: str, data_dir: Path
) -> None:
    """The grants in migration 0002 are sufficient for everything the backend does."""
    settings = make_settings(token, workspace, data_dir, database_url=runtime_url)
    with TestClient(create_app(settings, make_allowlist()), base_url="http://127.0.0.1") as c:
        c.headers["Authorization"] = f"Bearer {token}"
        checks = {x["name"]: x for x in c.get("/api/v1/health").json()["checks"]}
        assert checks["audit_protection"]["ok"] is True, checks["audit_protection"]

        r = run_action(c, workspace, "git", ["status"])
        assert wait_job(c, r.json()["job_id"])["status"] == "completed"
        appr = run_action(c, workspace, "pyproc-l2", L2_CODE).json()["approval"]
        c.post(f"/api/v1/approvals/{appr['id']}/approve")
        r = run_action(c, workspace, "pyproc-l2", L2_CODE, approval_id=appr["id"])
        assert wait_job(c, r.json()["job_id"])["status"] == "completed"
        tok = c.post("/api/v1/agents/credentials", json={"agent_id": "codex"}).json()["token"]
        assert c.get("/api/v1/catalog", headers=as_agent(tok)).status_code == 200

        assert c.post("/api/v1/system/emergency-stop").json()["persisted"] is True
        reset = c.post("/api/v1/actions", json={"action": "system.emergency_reset", "params": {}})
        rid = reset.json()["approval"]["id"]
        c.post(f"/api/v1/approvals/{rid}/approve")
        done = c.post(
            "/api/v1/actions",
            json={"action": "system.emergency_reset", "params": {}, "approval_id": rid},
        )
        assert done.status_code == 200, done.text
        assert c.get("/api/v1/audit/verify").json()["ok"] is True


def test_health_flags_an_owner_connection(client: TestClient) -> None:
    checks = {x["name"]: x for x in client.get("/api/v1/health").json()["checks"]}
    assert checks["audit_protection"]["ok"] is False
    assert "owner" in checks["audit_protection"]["detail"]
