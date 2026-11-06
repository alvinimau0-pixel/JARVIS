"""API integration tests against real PostgreSQL: lifecycle, events, health, audit."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.conftest import run_action, wait_job

pytestmark = pytest.mark.db


def test_liveness_is_public_and_minimal(client: TestClient) -> None:
    r = client.get("/api/v1/health/live", headers={"Authorization": ""})
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_health_reports_real_checks(client: TestClient) -> None:
    body = client.get("/api/v1/health").json()
    checks = {c["name"]: c for c in body["checks"]}
    assert checks["database"]["ok"] and checks["migrations"]["ok"]
    assert checks["emergency_stop"]["detail"] == "clear"


def test_catalog_lists_actions_and_levels(client: TestClient, workspace: Path) -> None:
    body = client.get("/api/v1/catalog").json()
    names = {a["name"] for a in body["actions"]}
    assert {"exec.run", "system.emergency_reset"} <= names
    levels = {e["name"]: e["level"] for e in body["executables"]}
    assert levels["git"] == 0 and levels["git-push"] == 2
    assert body["workspaces"] == [workspace.name]


def test_l0_git_status_runs_end_to_end(client: TestClient, workspace: Path) -> None:
    r = run_action(client, workspace, "git", ["status", "--porcelain"])
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["status"] == "accepted" and body["level"] == 0
    job = wait_job(client, body["job_id"])
    assert job["status"] == "completed" and job["exit_code"] == 0
    assert "README.md" in job["stdout"]


def test_failed_command_is_reported_as_failed(client: TestClient, workspace: Path) -> None:
    r = run_action(client, workspace, "pyproc", ["-c", "import sys; sys.exit(7)"])
    job = wait_job(client, r.json()["job_id"])
    assert job["status"] == "failed" and job["exit_code"] == 7
    tasks = client.get("/api/v1/tasks").json()
    assert any(t["id"] == job["task_id"] and t["status"] == "failed" for t in tasks)


def test_timeout_marks_job_timed_out(client: TestClient, workspace: Path) -> None:
    body = {
        "action": "exec.run",
        "params": {
            "executable": "pyproc",
            "workspace": workspace.name,
            "args": ["-c", "import time; time.sleep(30)"],
            "timeout_s": 1,
        },
    }
    r = client.post("/api/v1/actions", json=body)
    job = wait_job(client, r.json()["job_id"])
    assert job["status"] == "timed_out"


def test_events_are_ordered_and_describe_lifecycle(client: TestClient, workspace: Path) -> None:
    start = client.get("/api/v1/events", params={"since_seq": 0, "limit": 500}).json()
    since = start[-1]["seq"] if start else 0
    r = run_action(client, workspace, "git", ["status"])
    wait_job(client, r.json()["job_id"])
    events = client.get("/api/v1/events", params={"since_seq": since}).json()
    mine = [e for e in events if e["job_id"] == r.json()["job_id"]]
    types = [e["type"] for e in mine]
    assert types == ["task.created", "job.started", "job.completed"], types
    seqs = [e["seq"] for e in events]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)
    assert len({e["id"] for e in events}) == len(events)


def test_websocket_streams_live_events_in_order(
    client: TestClient, workspace: Path, token: str
) -> None:
    with client.websocket_connect(
        "ws://127.0.0.1/api/v1/ws", subprotocols=["jarvis.v1", f"auth.{token}"]
    ) as ws:
        r = run_action(client, workspace, "git", ["status"])
        job_id = r.json()["job_id"]
        got: list[dict[str, Any]] = []
        while not any(
            e["type"] == "task.completed" and e["task_id"] == r.json()["task_id"] for e in got
        ):
            got.append(ws.receive_json())
    mine = [e["type"] for e in got if e.get("job_id") == job_id]
    assert mine == ["task.created", "job.started", "job.completed"]
    assert [e["seq"] for e in got] == sorted(e["seq"] for e in got)


def test_websocket_replays_missed_events(client: TestClient, workspace: Path, token: str) -> None:
    r = run_action(client, workspace, "git", ["status"])
    wait_job(client, r.json()["job_id"])
    first = client.get("/api/v1/events", params={"since_seq": 0, "limit": 500}).json()
    target = next(e for e in first if e["job_id"] == r.json()["job_id"])
    with client.websocket_connect(
        f"ws://127.0.0.1/api/v1/ws?since_seq={target['seq'] - 1}",
        subprotocols=["jarvis.v1", f"auth.{token}"],
    ) as ws:
        replayed = ws.receive_json()
    assert replayed["id"] == target["id"]


def test_every_action_is_audited_and_chain_verifies(client: TestClient, workspace: Path) -> None:
    before = client.get("/api/v1/audit/count").json()["count"]
    r = run_action(client, workspace, "git", ["status"])
    wait_job(client, r.json()["job_id"])
    run_action(client, workspace, "bash", ["-c", "id"])  # denied, still audited
    after = client.get("/api/v1/audit/count").json()["count"]
    assert after - before >= 3  # allowed + job.finished + denied
    entries = client.get("/api/v1/audit", params={"limit": 5}).json()
    assert any(e["decision"] == "denied" for e in entries)
    assert client.get("/api/v1/audit/verify").json()["ok"] is True
