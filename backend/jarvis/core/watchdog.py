"""Parent-process watchdog: the backend exits when the desktop shell that launched it is gone.

Covers the case where the shell crashes or `child.kill()` only reaches an intermediate launcher
(e.g. `uv run` on Windows), which would otherwise leave an authenticated backend running.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from collections.abc import Awaitable, Callable

log = logging.getLogger(__name__)


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes

        process_query_limited_information = 0x1000
        still_active = 259
        k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = k32.OpenProcess(process_query_limited_information, False, pid)
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            if not k32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return code.value == still_active
        finally:
            k32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # A zombie has exited but not been reaped yet: it is not alive.
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as fh:
            return fh.read().rsplit(")", 1)[-1].split()[0] != "Z"
    except OSError:
        return True  # no /proc (macOS): kill(0) succeeding is the best signal available


async def watch_parent(
    pid: int, on_gone: Callable[[], Awaitable[None]], interval_s: float = 2.0
) -> None:
    while True:
        await asyncio.sleep(interval_s)
        if not pid_alive(pid):
            log.warning("parent process %s is gone; shutting down", pid)
            await on_gone()
            return
