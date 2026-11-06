"""Unit tests: policy, path containment, approval hashing, argument validation, redaction."""

from __future__ import annotations

import logging
import os
from pathlib import Path

import pytest

from jarvis.core.redaction import REDACTED, RedactingFilter, redact, redact_text, register_secret
from jarvis.exec.allowlist import (
    Allowlist,
    ArgumentRejected,
    ExecutableRule,
    validate_git_push,
    validate_git_read,
    validate_pytest,
)
from jarvis.security.hashing import action_hash
from jarvis.security.paths import WorkspaceViolation, resolve_in_workspace
from jarvis.security.policy import Decision, DenyCode, Level, PolicyEngine
from jarvis.security.principal import Principal


# ------------------------------------------------------------------ paths
@pytest.fixture()
def ws(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    (root / "src").mkdir(parents=True)
    (tmp_path / "secret").mkdir()
    return root


@pytest.mark.parametrize("rel", ["src", ".", "src/../src", "./src"])
def test_paths_inside_workspace_are_allowed(ws: Path, rel: str) -> None:
    assert str(resolve_in_workspace(ws, rel)).startswith(os.path.realpath(ws))


@pytest.mark.parametrize(
    "rel",
    [
        "..",
        "../secret",
        "src/../../secret",
        "/etc",
        "C:\\Windows",
        "c:/windows",
        "\\\\server\\share",
        "//server/share",
        "\\rooted",
        "src\x00",
    ],
)
def test_paths_escaping_workspace_are_rejected(ws: Path, rel: str) -> None:
    with pytest.raises(WorkspaceViolation):
        resolve_in_workspace(ws, rel)


def test_symlink_escape_is_rejected(ws: Path, tmp_path: Path) -> None:
    (ws / "link").symlink_to(tmp_path / "secret", target_is_directory=True)
    with pytest.raises(WorkspaceViolation):
        resolve_in_workspace(ws, "link")


def test_prefix_sibling_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    (tmp_path / "proj-evil").mkdir()
    with pytest.raises(WorkspaceViolation):
        resolve_in_workspace(root, "../proj-evil")


# ------------------------------------------------------------- arguments
def test_git_read_allows_status_and_adds_hardening() -> None:
    argv = validate_git_read(["status", "--porcelain"])
    assert argv[-2:] == ["status", "--porcelain"]
    assert "core.fsmonitor=false" in argv and "--no-pager" in argv


def test_git_diff_disables_external_tools() -> None:
    argv = validate_git_read(["diff"])
    assert "--no-ext-diff" in argv and "--no-textconv" in argv


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["push"],
        ["commit", "-m", "x"],
        ["status", "-c", "core.pager=sh"],
        ["log", "--output=/tmp/x"],
        ["diff", "--ext-diff"],
        ["status", "--git-dir=/etc"],
        ["branch", "-D", "main"],
        ["status", "bad\narg"],
    ],
)
def test_git_read_rejects_dangerous_args(args: list[str]) -> None:
    with pytest.raises(ArgumentRejected):
        validate_git_read(args)


@pytest.mark.parametrize(
    "args", [["--force"], ["origin", "+main"], ["origin", ":main"], ["a", "b", "c"]]
)
def test_git_push_rejects_force_delete_and_flags(args: list[str]) -> None:
    with pytest.raises(ArgumentRejected):
        validate_git_push(args)


def test_pytest_validation() -> None:
    assert validate_pytest(["-m", "pytest", "-q"]) == ["-m", "pytest", "-q"]
    for bad in (["-c", "print(1)"], ["script.py"], ["-m", "pytest", "-p", "evil"], ["-m", "pip"]):
        with pytest.raises(ArgumentRejected):
            validate_pytest(bad)


# ------------------------------------------------------------------ policy
def _engine(ws: Path) -> PolicyEngine:
    allow = Allowlist()
    allow.add(ExecutableRule("git", "/usr/bin/git", validate_git_read, 0))
    allow.add(ExecutableRule("python", "/usr/bin/python3", validate_pytest, 1))
    allow.add(ExecutableRule("git-push", "/usr/bin/git", validate_git_push, 2))
    return PolicyEngine(allowlist=allow, workspaces=[ws], default_timeout_s=10, max_timeout_s=60)


def _run(ws: Path, exe: str, args: list[str], **extra: object) -> dict[str, object]:
    return {"executable": exe, "args": args, "workspace": ws.name, **extra}


def test_policy_levels(ws: Path) -> None:
    eng, human = _engine(ws), Principal.operator()
    r0 = eng.evaluate(human, "exec.run", _run(ws, "git", ["status"]), emergency_latched=False)
    assert (r0.decision, r0.level) == (Decision.ALLOW, Level.L0_READ)
    r1 = eng.evaluate(
        human, "exec.run", _run(ws, "python", ["-m", "pytest"]), emergency_latched=False
    )
    assert (r1.decision, r1.level) == (Decision.ALLOW, Level.L1_ROUTINE)
    r2 = eng.evaluate(
        human, "exec.run", _run(ws, "git-push", ["origin", "main"]), emergency_latched=False
    )
    assert (r2.decision, r2.level) == (Decision.REQUIRE_APPROVAL, Level.L2_SENSITIVE)
    r3 = eng.evaluate(human, "system.emergency_reset", {}, emergency_latched=True)
    assert (r3.decision, r3.level) == (Decision.REQUIRE_APPROVAL, Level.L3_CRITICAL)


def test_policy_denials(ws: Path) -> None:
    eng, human = _engine(ws), Principal.operator()
    cases = [
        ("nope", {}, DenyCode.UNKNOWN_ACTION),
        ("exec.run", _run(ws, "bash", ["-c", "rm -rf /"]), DenyCode.NOT_ALLOWLISTED),
        ("exec.run", _run(ws, "git", ["status"], cwd="../.."), DenyCode.WORKSPACE),
        ("exec.run", {**_run(ws, "git", ["status"]), "workspace": "other"}, DenyCode.WORKSPACE),
        ("exec.run", {**_run(ws, "git", ["status"]), "shell": True}, DenyCode.INVALID_PARAMS),
        ("exec.run", "not-a-dict", DenyCode.INVALID_PARAMS),
    ]
    for action, params, code in cases:
        res = eng.evaluate(human, action, params, emergency_latched=False)  # type: ignore[arg-type]
        assert res.decision is Decision.DENY and res.code is code, (action, params, res)


def test_agent_cannot_touch_policy(ws: Path) -> None:
    res = _engine(ws).evaluate(
        Principal.agent("codex"), "system.emergency_reset", {}, emergency_latched=True
    )
    assert res.decision is Decision.DENY and res.code is DenyCode.AGENT_POLICY


def test_emergency_latch_blocks_execution(ws: Path) -> None:
    res = _engine(ws).evaluate(
        Principal.operator(), "exec.run", _run(ws, "git", ["status"]), emergency_latched=True
    )
    assert res.decision is Decision.DENY and res.code is DenyCode.EMERGENCY_STOP


def test_timeout_is_capped(ws: Path) -> None:
    res = _engine(ws).evaluate(
        Principal.operator(),
        "exec.run",
        _run(ws, "git", ["status"], timeout_s=99999),
        emergency_latched=False,
    )
    assert res.plan is not None and res.plan.timeout_s == 60


# ----------------------------------------------------------------- hashing
def test_action_hash_binds_params() -> None:
    a = action_hash("exec.run", {"args": ["origin", "main"], "x": 1})
    assert a == action_hash("exec.run", {"x": 1, "args": ["origin", "main"]})  # key order
    assert a != action_hash("exec.run", {"args": ["origin", "evil"], "x": 1})
    assert a != action_hash("exec.other", {"args": ["origin", "main"], "x": 1})


# --------------------------------------------------------------- redaction
@pytest.mark.parametrize(
    "secret",
    [
        "sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
        "sk-proj-abcdefghijklmnopqrstuvwx",
        "ghp_abcdefghijklmnopqrstuvwxyz0123",
        "AKIAABCDEFGHIJKLMNOP",
    ],
)
def test_known_secret_formats_are_redacted(secret: str) -> None:
    out = redact_text(f"leaked {secret} here")
    assert secret not in out and REDACTED in out


def test_redaction_of_assignments_urls_and_registered_values() -> None:
    register_secret("per-launch-session-token-value-123")
    text = (
        "password=hunter2 Authorization: Bearer abcdefghijklmnopqrstuvwxyz "
        "postgresql+psycopg://jarvis:topsecret@localhost/db per-launch-session-token-value-123"
    )
    out = redact_text(text)
    for leaked in (
        "hunter2",
        "abcdefghijklmnopqrstuvwxyz",
        "topsecret",
        "per-launch-session-token",
    ):
        assert leaked not in out
    assert "postgresql+psycopg://jarvis:" in out  # structure kept for debugging


def test_redact_nested_structures_and_sensitive_keys() -> None:
    out = redact({"api_key": "plain", "nested": [{"note": "token=abc123def"}], "ok": 3})
    assert out["api_key"] == REDACTED
    assert "abc123def" not in out["nested"][0]["note"]
    assert out["ok"] == 3


def test_logging_filter_redacts(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("jarvis.test")
    logger.addFilter(RedactingFilter())
    with caplog.at_level(logging.INFO, logger="jarvis.test"):
        logger.info("calling provider with %s", "sk-ant-api03-zzzzzzzzzzzzzzzzzzzz")
    assert "sk-ant-api03" not in caplog.text
    assert REDACTED in caplog.text


def test_default_allowlist_keeps_virtualenv_interpreter() -> None:
    import shutil

    from jarvis.exec.allowlist import default_allowlist

    rule = default_allowlist().rules.get("python")
    found = shutil.which("python3") or shutil.which("python")
    assert rule is not None and found is not None
    assert rule.path == os.path.abspath(found)  # symlink not resolved away from the venv
