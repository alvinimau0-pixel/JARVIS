"""Controlled child-process runner: argv only, scrubbed env, timeouts, output caps, tracking."""

from __future__ import annotations

import asyncio
import os
import sys
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from jarvis.core.redaction import redact_text
from jarvis.exec.allowlist import ExecutableRule
from jarvis.exec.proctree import KillOutcome, ProcessTree, popen_kwargs

_ENV_KEEP = (
    "PATH",
    "HOME",
    "USERPROFILE",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "PATHEXT",
    "APPDATA",
    "LOCALAPPDATA",
)


def scrubbed_env() -> dict[str, str]:
    """Minimal environment. Credentials in the parent environment are never inherited."""
    env = {k: v for k, v in os.environ.items() if k.upper() in _ENV_KEEP}
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


@dataclass
class ExecResult:
    exit_code: int | None
    stdout: str
    stderr: str
    truncated: bool
    timed_out: bool
    cancelled: bool
    duration_s: float
    kill: KillOutcome | None = None


@dataclass
class _Tracked:
    tree: ProcessTree
    cancel: asyncio.Event = field(default_factory=asyncio.Event)


class ProcessRegistry:
    """Every live controlled child, keyed by job id. Used by cancellation and emergency stop."""

    def __init__(self) -> None:
        self._procs: dict[uuid.UUID, _Tracked] = {}

    def _add(self, job_id: uuid.UUID, tracked: _Tracked) -> None:
        self._procs[job_id] = tracked

    def _remove(self, job_id: uuid.UUID) -> None:
        tracked = self._procs.pop(job_id, None)
        if tracked:
            tracked.tree.close()

    def active(self) -> list[uuid.UUID]:
        return list(self._procs)

    def pid_of(self, job_id: uuid.UUID) -> int | None:
        tracked = self._procs.get(job_id)
        return tracked.tree.pid if tracked else None

    def cancel(self, job_id: uuid.UUID) -> KillOutcome | None:
        tracked = self._procs.get(job_id)
        if tracked is None:
            return None
        tracked.cancel.set()
        return tracked.tree.kill()

    def kill_all(self) -> list[KillOutcome]:
        outcomes = []
        for job_id in list(self._procs):
            outcome = self.cancel(job_id)
            if outcome is not None:
                outcomes.append(outcome)
        return outcomes


async def _read_capped(
    stream: asyncio.StreamReader, budget: list[int], chunks: list[bytes]
) -> bool:
    truncated = False
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            return truncated
        if budget[0] > 0:
            keep = chunk[: budget[0]]
            chunks.append(keep)
            budget[0] -= len(keep)
            if len(keep) < len(chunk):
                truncated = True
        else:
            truncated = True  # keep draining so the child never blocks on a full pipe


async def run_controlled(
    *,
    rule: ExecutableRule,
    argv_tail: list[str],
    cwd: Path,
    timeout_s: float,
    output_limit: int,
    registry: ProcessRegistry,
    job_id: uuid.UUID,
    on_started: object = None,
    should_abort: Callable[[], bool] | None = None,
) -> ExecResult:
    """Run ``rule.path`` with ``argv_tail`` (already validated). Never uses a shell."""
    started = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        rule.path,
        *argv_tail,
        cwd=str(cwd),
        env=scrubbed_env(),
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        **popen_kwargs(),
    )
    try:
        tree = ProcessTree(proc.pid)
    except OSError:
        proc.kill()
        await proc.wait()
        raise
    tracked = _Tracked(tree)
    registry._add(job_id, tracked)
    # Close the start-up race: a stop/cancel issued while the process was being created could
    # not see it in the registry. Re-check now that it is registered and kill immediately.
    if should_abort is not None and should_abort():
        tracked.cancel.set()
        await asyncio.to_thread(tree.kill)
    if callable(on_started):
        res = on_started(proc.pid)
        if asyncio.iscoroutine(res):
            await res

    budget = [output_limit]
    out_chunks: list[bytes] = []
    err_chunks: list[bytes] = []
    assert proc.stdout is not None and proc.stderr is not None
    readers = asyncio.gather(
        _read_capped(proc.stdout, budget, out_chunks),
        _read_capped(proc.stderr, budget, err_chunks),
    )
    timed_out = False
    kill: KillOutcome | None = None
    try:
        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout_s)
        except TimeoutError:
            timed_out = True
            kill = await asyncio.to_thread(tree.kill)
            await proc.wait()
        # Descendants may still hold the pipes open; bound how long we wait for EOF.
        try:
            trunc_out, trunc_err = await asyncio.wait_for(readers, timeout=5)
        except TimeoutError:
            kill = kill or await asyncio.to_thread(tree.kill)
            trunc_out, trunc_err = await asyncio.wait_for(readers, timeout=5)
        if tree.alive():
            # Leader exited but descendants remain in the group: they are ours to clean up.
            kill = kill or await asyncio.to_thread(tree.kill)
    finally:
        registry._remove(job_id)

    def decode(chunks: list[bytes]) -> str:
        return redact_text(b"".join(chunks).decode("utf-8", errors="replace"))

    return ExecResult(
        exit_code=proc.returncode,
        stdout=decode(out_chunks),
        stderr=decode(err_chunks),
        truncated=trunc_out or trunc_err,
        timed_out=timed_out,
        cancelled=tracked.cancel.is_set(),
        duration_s=round(time.monotonic() - started, 3),
        kill=kill,
    )


PYTHON = sys.executable
