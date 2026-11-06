"""Process-tree containment and termination.

POSIX: each child starts in its own session/process group; the whole group is killed.
Windows: each child is assigned to a Job Object with KILL_ON_JOB_CLOSE; the job is terminated.
The Windows path is UNTESTED ON TARGET in this build (see docs/KNOWN_ISSUES.md).
"""

from __future__ import annotations

import os
import signal
import sys
import time
from dataclasses import dataclass
from typing import Any

IS_WINDOWS = sys.platform == "win32"


@dataclass
class KillOutcome:
    pid: int
    stopped: bool
    detail: str


def popen_kwargs() -> dict[str, Any]:
    if IS_WINDOWS:
        import subprocess

        return {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200)}
    return {"start_new_session": True}


class _WindowsJob:
    """Thin ctypes wrapper around a Win32 Job Object."""

    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
    JobObjectExtendedLimitInformation = 9
    PROCESS_SET_QUOTA = 0x0100
    PROCESS_TERMINATE = 0x0001

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        self._ctypes = ctypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        self._k32 = kernel32
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")  # type: ignore[attr-defined]
        self.handle = handle

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [
                (n, ctypes.c_ulonglong)
                for n in (
                    "ReadOperationCount",
                    "WriteOperationCount",
                    "OtherOperationCount",
                    "ReadTransferCount",
                    "WriteTransferCount",
                    "OtherTransferCount",
                )
            ]

        class BASIC(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class EXTENDED(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BASIC),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        info = EXTENDED()
        info.BasicLimitInformation.LimitFlags = self.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        ok = kernel32.SetInformationJobObject(
            handle, self.JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info)
        )
        if not ok:
            raise OSError(ctypes.get_last_error(), "SetInformationJobObject failed")  # type: ignore[attr-defined]

    def assign(self, pid: int) -> None:
        k32 = self._k32
        proc = k32.OpenProcess(self.PROCESS_SET_QUOTA | self.PROCESS_TERMINATE, False, pid)
        if not proc:
            raise OSError(self._ctypes.get_last_error(), "OpenProcess failed")  # type: ignore[attr-defined]
        try:
            if not k32.AssignProcessToJobObject(self.handle, proc):
                raise OSError(self._ctypes.get_last_error(), "AssignProcessToJobObject failed")  # type: ignore[attr-defined]
        finally:
            k32.CloseHandle(proc)

    def terminate(self) -> bool:
        return bool(self._k32.TerminateJobObject(self.handle, 1))

    def close(self) -> None:
        if self.handle:
            self._k32.CloseHandle(self.handle)
            self.handle = None


class ProcessTree:
    """Handle to a spawned child and all of its descendants."""

    def __init__(self, pid: int) -> None:
        self.pid = pid
        self._job: _WindowsJob | None = None
        if IS_WINDOWS:
            job = _WindowsJob()
            job.assign(pid)
            self._job = job

    def kill(self, grace_seconds: float = 2.0) -> KillOutcome:
        if IS_WINDOWS:
            assert self._job is not None
            ok = self._job.terminate()
            return KillOutcome(
                self.pid, ok, "job terminated" if ok else "TerminateJobObject failed"
            )
        return _kill_posix_group(self.pid, grace_seconds)

    def alive(self) -> bool:
        if IS_WINDOWS:
            return False  # job termination is authoritative; see kill()
        try:
            os.killpg(self.pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def close(self) -> None:
        if self._job is not None:
            self._job.close()


def _kill_posix_group(pgid: int, grace_seconds: float) -> KillOutcome:
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return KillOutcome(pgid, True, "already exited")
    deadline = time.monotonic() + grace_seconds
    while time.monotonic() < deadline:
        if not _group_has_live_members(pgid):
            return KillOutcome(pgid, True, "terminated (SIGTERM)")
        time.sleep(0.05)
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        return KillOutcome(pgid, True, "terminated (SIGTERM)")
    deadline = time.monotonic() + grace_seconds
    while time.monotonic() < deadline:
        if not _group_has_live_members(pgid):
            return KillOutcome(pgid, True, "killed (SIGKILL)")
        time.sleep(0.05)
    return KillOutcome(pgid, False, "process group still has live members after SIGKILL")


def _group_has_live_members(pgid: int) -> bool:
    """True if any non-zombie process is still in the group (Linux /proc aware)."""
    proc = "/proc"
    if os.path.isdir(proc):
        for entry in os.listdir(proc):
            if not entry.isdigit():
                continue
            try:
                with open(f"{proc}/{entry}/stat", encoding="utf-8") as fh:
                    stat = fh.read()
            except OSError:
                continue
            # Fields after the "(comm)" token: state ppid pgrp ...
            rest = stat.rsplit(")", 1)[-1].split()
            if len(rest) >= 3 and int(rest[2]) == pgid and rest[0] != "Z":
                return True
        return False
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    return True
