"""Controlled runner: real child processes, timeouts, output caps, tree kill."""

from __future__ import annotations

import asyncio
import sys
import uuid
from pathlib import Path

import pytest

from jarvis.exec.runner import ProcessRegistry, run_controlled, scrubbed_env
from tests.helpers import SPAWN_TREE, pyproc_rule

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX tree semantics")


def _alive(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().rsplit(")", 1)[-1].split()[0] != "Z"
    except FileNotFoundError:
        return False


async def _run(
    tmp_path: Path,
    code: str,
    *,
    timeout: float = 10,
    limit: int = 1 << 16,
    registry: ProcessRegistry | None = None,
    job: uuid.UUID | None = None,
):
    return await run_controlled(
        rule=pyproc_rule(),
        argv_tail=["-c", code],
        cwd=tmp_path,
        timeout_s=timeout,
        output_limit=limit,
        registry=registry or ProcessRegistry(),
        job_id=job or uuid.uuid4(),
    )


async def test_runs_and_captures_output(tmp_path: Path) -> None:
    expected = str(tmp_path.resolve())
    res = await _run(tmp_path, "import os;print(os.getcwd())")
    assert res.exit_code == 0 and res.stdout.strip() == expected


async def test_nonzero_exit_reported(tmp_path: Path) -> None:
    res = await _run(tmp_path, "import sys;sys.stderr.write('boom');sys.exit(3)")
    assert res.exit_code == 3 and "boom" in res.stderr


async def test_output_cap_truncates_without_deadlock(tmp_path: Path) -> None:
    res = await _run(tmp_path, "print('x'*500000)", limit=1000)
    assert res.truncated and len(res.stdout) <= 1000 and res.exit_code == 0


async def test_timeout_kills_whole_tree(tmp_path: Path) -> None:
    res = await _run(tmp_path, SPAWN_TREE, timeout=1.5)
    assert res.timed_out and res.kill is not None and res.kill.stopped
    _, parent, child = res.stdout.split()
    await asyncio.sleep(0.2)
    assert not _alive(int(parent)) and not _alive(int(child))


async def test_cancel_kills_tree(tmp_path: Path) -> None:
    reg, job = ProcessRegistry(), uuid.uuid4()
    task = asyncio.create_task(_run(tmp_path, SPAWN_TREE, timeout=60, registry=reg, job=job))
    for _ in range(100):
        if reg.pid_of(job):
            break
        await asyncio.sleep(0.05)
    await asyncio.sleep(0.5)  # let the grandchild start
    outcome = await asyncio.to_thread(reg.cancel, job)
    assert outcome is not None and outcome.stopped
    res = await task
    assert res.cancelled
    _, parent, child = res.stdout.split()
    assert not _alive(int(parent)) and not _alive(int(child))
    assert reg.active() == []


async def test_orphaned_grandchild_is_cleaned_up(tmp_path: Path) -> None:
    code = (
        "import subprocess,sys;"
        "c=subprocess.Popen([sys.executable,'-c','import time; time.sleep(120)'],"
        "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);print(c.pid)"
    )
    res = await _run(tmp_path, code)
    await asyncio.sleep(0.2)
    assert not _alive(int(res.stdout.strip())), "leader exited but its descendant survived"


def test_env_is_scrubbed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-should-not-leak")
    monkeypatch.setenv("JARVIS_SESSION_TOKEN", "nope")
    env = scrubbed_env()
    assert "OPENAI_API_KEY" not in env and "JARVIS_SESSION_TOKEN" not in env
    assert "PATH" in env


async def test_secrets_in_output_are_redacted(tmp_path: Path) -> None:
    res = await _run(tmp_path, "print('key: sk-ant-api03-aaaaaaaaaaaaaaaaaaaa')")
    assert "sk-ant-api03" not in res.stdout
