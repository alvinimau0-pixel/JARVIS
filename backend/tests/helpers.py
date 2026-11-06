"""Test-only allowlist entries. These never ship in default_allowlist()."""

from __future__ import annotations

import sys
from collections.abc import Sequence

from jarvis.exec.allowlist import ArgumentRejected, ExecutableRule


def _python_c(args: Sequence[str]) -> list[str]:
    if len(args) != 2 or args[0] != "-c":
        raise ArgumentRejected("test runner accepts only -c <code>")
    return list(args)


def pyproc_rule(level: int = 1, name: str = "pyproc") -> ExecutableRule:
    return ExecutableRule(name, sys.executable, _python_c, level, "TEST ONLY: python -c")


# Spawns a grandchild that sleeps, prints both PIDs, then sleeps itself.
SPAWN_TREE = (
    "import subprocess,sys,time;"
    "c=subprocess.Popen([sys.executable,'-c','import time; time.sleep(120)']);"
    "print('PIDS',__import__('os').getpid(),c.pid,flush=True);"
    "time.sleep(120)"
)
