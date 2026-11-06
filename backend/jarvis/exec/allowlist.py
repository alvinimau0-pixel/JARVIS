"""Executable allowlist with per-executable argument validation.

Models never supply a command string. They name an allowlisted executable and an argv list,
and each entry's validator decides which arguments are acceptable.
"""

from __future__ import annotations

import os
import re
import shutil
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field


class ArgumentRejected(ValueError):
    pass


Validator = Callable[[Sequence[str]], list[str]]
"""Validates arguments and returns the final argv tail (may prepend hardening flags)."""


@dataclass(frozen=True)
class ExecutableRule:
    name: str
    path: str
    validate: Validator
    level: int  # permission level (0-3) of running this executable
    description: str = ""


@dataclass
class Allowlist:
    rules: dict[str, ExecutableRule] = field(default_factory=dict)

    def add(self, rule: ExecutableRule) -> None:
        self.rules[rule.name] = rule

    def get(self, name: str) -> ExecutableRule:
        rule = self.rules.get(name)
        if rule is None:
            raise ArgumentRejected(f"executable '{name}' is not allowlisted")
        return rule

    def names(self) -> list[str]:
        return sorted(self.rules)


def _no_control_chars(args: Sequence[str]) -> None:
    for arg in args:
        if not isinstance(arg, str):
            raise ArgumentRejected("arguments must be strings")
        if any(ord(c) < 32 for c in arg):
            raise ArgumentRejected("arguments may not contain control characters")
        if len(arg) > 4096:
            raise ArgumentRejected("argument too long")


# --------------------------------------------------------------------------- shared rules
_DRIVE = re.compile(r"^[A-Za-z]:")


def _check_relative_operand(arg: str) -> None:
    """Positional operands (paths, revisions, test ids) must stay inside the workspace."""
    if arg.startswith(("/", "\\")) or _DRIVE.match(arg) or arg.startswith("~"):
        raise ArgumentRejected(f"absolute or home-relative operand '{arg}' is not allowed")
    if any(part == ".." for part in re.split(r"[/\\]", arg)):
        raise ArgumentRejected(f"operand '{arg}' may not contain '..' path components")


_INT = re.compile(r"^\d{1,6}$")

# --------------------------------------------------------------------------------- git read
# Exact flag allowlists per subcommand. Anything else is rejected, which also defeats git's
# acceptance of abbreviated long options (e.g. "--ext-d" for "--ext-diff").
_GIT_FLAGS: dict[str, frozenset[str]] = {
    "status": frozenset({"--porcelain", "--porcelain=v1", "--porcelain=v2", "-s", "--short",
                         "-b", "--branch", "--untracked-files=no", "--untracked-files=normal",
                         "--untracked-files=all", "-uno", "-unormal", "-uall"}),
    "diff": frozenset({"--stat", "--name-only", "--name-status", "--cached", "--staged",
                       "--numstat", "--shortstat", "--color=never", "--no-color"}),
    "log": frozenset({"--oneline", "--stat", "--name-only", "--name-status", "--graph",
                      "--decorate", "--no-merges", "--all", "--reverse", "--no-color"}),
    "show": frozenset({"--stat", "--name-only", "--name-status", "--oneline", "--no-color",
                       "--no-patch", "-s"}),
    "rev-parse": frozenset({"--abbrev-ref", "--short", "--verify", "--show-toplevel",
                            "--is-inside-work-tree"}),
    "branch": frozenset({"--list", "-a", "--all", "-r", "--remotes", "--show-current", "-v",
                         "-vv", "--no-color"}),
    "ls-files": frozenset({"-c", "--cached", "-o", "--others", "-m", "--modified", "-d",
                           "--deleted", "--exclude-standard"}),
}  # fmt: skip
GIT_READ_SUBCOMMANDS = frozenset(_GIT_FLAGS)
_GIT_VALUE_FLAGS = re.compile(r"^--(format|pretty|max-count|since|until|author)=[^\n]{0,200}$")
_GIT_TAKES_OPERANDS = frozenset({"diff", "log", "show", "rev-parse", "ls-files"})

# Hardening applied by JARVIS (never by the caller): disable repository-configured hooks,
# fsmonitor commands, external diff tools, pagers and signature verification programs.
_GIT_HARDENING = [
    "-c", "core.fsmonitor=false",
    "-c", f"core.hooksPath={os.devnull}",
    "-c", "core.pager=cat",
    "-c", "diff.external=",
    "-c", "protocol.ext.allow=never",
    "-c", "log.showSignature=false",
    "--no-pager",
]  # fmt: skip


def validate_git_read(args: Sequence[str]) -> list[str]:
    _no_control_chars(args)
    if not args or args[0] not in _GIT_FLAGS:
        raise ArgumentRejected(f"git subcommand must be one of {sorted(GIT_READ_SUBCOMMANDS)}")
    sub, rest = args[0], list(args[1:])
    allowed = _GIT_FLAGS[sub]
    after_separator = False
    i = 0
    while i < len(rest):
        arg = rest[i]
        if after_separator or not arg.startswith("-"):
            if sub not in _GIT_TAKES_OPERANDS:
                raise ArgumentRejected(f"git {sub} does not accept operands here ('{arg}')")
            _check_relative_operand(arg)
        elif arg == "--":
            after_separator = True
        elif arg in allowed:
            pass
        elif sub == "log" and arg == "-n" and i + 1 < len(rest) and _INT.match(rest[i + 1]):
            i += 1
        elif sub == "log" and re.match(r"^-\d{1,6}$", arg):
            pass
        elif sub in {"log", "show"} and _GIT_VALUE_FLAGS.match(arg):
            pass
        else:
            raise ArgumentRejected(f"git {sub} option '{arg}' is not allowed")
        i += 1
    tail = [sub, *rest]
    if sub in {"diff", "log", "show"}:
        tail = [sub, "--no-ext-diff", "--no-textconv", *rest]
    return [*_GIT_HARDENING, *tail]


_GIT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")


def validate_git_push(args: Sequence[str]) -> list[str]:
    _no_control_chars(args)
    # Only `git push [remote] [branch]` with plain names. No flags, force, refspecs or deletes.
    if len(args) > 2:
        raise ArgumentRejected("git push accepts only [remote] [branch]")
    for arg in args:
        if not _GIT_NAME.match(arg) or ".." in arg or arg.endswith((".lock", "/")):
            raise ArgumentRejected(f"git push operand '{arg}' is not a plain remote/branch name")
    return [*_GIT_HARDENING, "push", *args]


# ------------------------------------------------------------------------------- pytest
_PYTEST_FLAGS = frozenset({"-q", "-v", "-vv", "-x", "-s", "-l", "--lf", "--ff", "--co",
                           "--collect-only", "--no-header", "--exitfirst", "--last-failed",
                           "--failed-first", "-rA", "-ra", "--strict-markers"})  # fmt: skip
_PYTEST_VALUE = re.compile(
    r"^--(tb=(auto|long|short|line|native|no)|maxfail=\d{1,4}|durations=\d{1,4})$"
)


def validate_pytest(args: Sequence[str]) -> list[str]:
    """`python -m pytest` with a small flag allowlist and workspace-relative test paths.

    Note: running tests executes the workspace's own code (conftest.py, test modules). That is
    the L1 "test inside approved workspaces" capability; the workspace itself must be trusted.
    """
    _no_control_chars(args)
    if list(args[:2]) != ["-m", "pytest"]:
        raise ArgumentRejected("python may only be invoked as 'python -m pytest'")
    rest = list(args[2:])
    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg == "-k" and i + 1 < len(rest) and len(rest[i + 1]) <= 200:
            i += 2
            continue
        if arg in _PYTEST_FLAGS or _PYTEST_VALUE.match(arg):
            pass
        elif arg.startswith("-"):
            raise ArgumentRejected(f"pytest option '{arg}' is not allowed")
        else:
            _check_relative_operand(arg.split("::", 1)[0])
        i += 1
    return list(args)


def _which(name: str) -> str | None:
    # Absolute, but NOT symlink-resolved: a virtualenv's python is a symlink, and resolving it
    # would run the base interpreter outside the venv. The path is fixed at startup either way.
    found = shutil.which(name)
    return os.path.abspath(found) if found else None


def default_allowlist() -> Allowlist:
    allow = Allowlist()
    git = _which("git")
    if git:
        allow.add(ExecutableRule("git", git, validate_git_read, 0, "read-only git inspection"))
        allow.add(ExecutableRule("git-push", git, validate_git_push, 2, "git push to a remote"))
    python = _which("python3") or _which("python")
    if python:
        allow.add(ExecutableRule("python", python, validate_pytest, 1, "python -m pytest"))
    return allow
