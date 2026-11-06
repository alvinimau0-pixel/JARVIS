"""Policy engine: every action is classified L0-L3 and decided here, in the backend.

Decisions:
  ALLOW             - L0/L1 inside an approved workspace.
  REQUIRE_APPROVAL  - L2/L3. Needs a human approval bound to the exact action+params hash.
  DENY              - unknown action, invalid params, workspace escape, agent touching policy,
                      or execution while the emergency stop is latched.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from jarvis.exec.allowlist import Allowlist, ArgumentRejected, ExecutableRule
from jarvis.security.paths import WorkspaceViolation, find_workspace, resolve_in_workspace
from jarvis.security.principal import Principal, PrincipalKind


class Level(IntEnum):
    L0_READ = 0
    L1_ROUTINE = 1
    L2_SENSITIVE = 2
    L3_CRITICAL = 3


class Decision(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class DenyCode(StrEnum):
    UNKNOWN_ACTION = "unknown_action"
    INVALID_PARAMS = "invalid_params"
    WORKSPACE = "workspace_violation"
    NOT_ALLOWLISTED = "not_allowlisted"
    AGENT_POLICY = "agent_cannot_modify_policy"
    EMERGENCY_STOP = "emergency_stop_active"


class ExecRunParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    executable: str = Field(min_length=1, max_length=64)
    args: list[str] = Field(default_factory=list, max_length=64)
    workspace: str = Field(min_length=1, max_length=255)
    cwd: str = Field(default=".", max_length=1024)
    timeout_s: float | None = Field(default=None, gt=0)


class EmptyParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


@dataclass(frozen=True)
class ActionSpec:
    name: str
    base_level: Level
    description: str
    params_model: type[BaseModel]
    mutates_policy: bool = False
    executes: bool = False  # blocked while the emergency stop is latched


ACTIONS: dict[str, ActionSpec] = {
    spec.name: spec
    for spec in (
        ActionSpec(
            "exec.run",
            Level.L0_READ,
            "Run an allowlisted executable inside an approved workspace "
            "(level comes from the executable rule).",
            ExecRunParams,
            executes=True,
        ),
        ActionSpec(
            "system.emergency_reset",
            Level.L3_CRITICAL,
            "Clear the emergency stop latch and allow execution again.",
            EmptyParams,
            mutates_policy=True,
        ),
    )
}


@dataclass(frozen=True)
class ExecPlan:
    rule: ExecutableRule
    argv_tail: list[str]
    cwd: Path
    timeout_s: float


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    action: str
    level: Level | None
    reason: str
    params: dict[str, Any] = field(default_factory=dict)
    target: str = ""
    code: DenyCode | None = None
    plan: ExecPlan | None = None


class PolicyEngine:
    def __init__(
        self,
        *,
        allowlist: Allowlist,
        workspaces: list[Path],
        default_timeout_s: float,
        max_timeout_s: float,
    ) -> None:
        self.allowlist = allowlist
        self.workspaces = workspaces
        self.default_timeout_s = default_timeout_s
        self.max_timeout_s = max_timeout_s

    def evaluate(
        self,
        principal: Principal,
        action: str,
        raw_params: dict[str, Any],
        *,
        emergency_latched: bool,
    ) -> PolicyResult:
        spec = ACTIONS.get(action)
        if spec is None:
            return self._deny(action, None, DenyCode.UNKNOWN_ACTION, f"unknown action '{action}'")

        if spec.mutates_policy and principal.kind is PrincipalKind.AGENT:
            return self._deny(
                action,
                spec.base_level,
                DenyCode.AGENT_POLICY,
                "agents may not change security policy or the emergency stop",
            )

        if spec.executes and emergency_latched:
            return self._deny(
                action,
                spec.base_level,
                DenyCode.EMERGENCY_STOP,
                "emergency stop is active; new execution is blocked",
            )

        try:
            params_obj = spec.params_model.model_validate(raw_params)
        except ValidationError as exc:
            return self._deny(action, spec.base_level, DenyCode.INVALID_PARAMS, _short(exc))
        params = params_obj.model_dump(mode="json")

        level = spec.base_level
        plan: ExecPlan | None = None
        target = action
        if isinstance(params_obj, ExecRunParams):
            try:
                plan = self._plan_exec(params_obj)
            except ArgumentRejected as exc:
                return self._deny(action, level, DenyCode.NOT_ALLOWLISTED, str(exc), params)
            except WorkspaceViolation as exc:
                return self._deny(action, level, DenyCode.WORKSPACE, str(exc), params)
            level = Level(max(level, plan.rule.level))
            target = (
                f"{params_obj.workspace}:{params_obj.cwd} $ {params_obj.executable} "
                + " ".join(params_obj.args)
            )

        if level >= Level.L2_SENSITIVE:
            return PolicyResult(
                Decision.REQUIRE_APPROVAL,
                action,
                level,
                f"L{int(level)} action requires explicit human approval",
                params,
                target,
                None,
                plan,
            )
        return PolicyResult(
            Decision.ALLOW,
            action,
            level,
            f"L{int(level)} action permitted",
            params,
            target,
            None,
            plan,
        )

    def _plan_exec(self, p: ExecRunParams) -> ExecPlan:
        rule = self.allowlist.get(p.executable)
        argv_tail = rule.validate(p.args)
        root = find_workspace(self.workspaces, p.workspace)
        cwd = resolve_in_workspace(root, p.cwd)
        if not cwd.is_dir():
            raise WorkspaceViolation("cwd is not a directory inside the workspace")
        timeout = min(p.timeout_s or self.default_timeout_s, self.max_timeout_s)
        return ExecPlan(rule, argv_tail, cwd, timeout)

    @staticmethod
    def _deny(
        action: str,
        level: Level | None,
        code: DenyCode,
        reason: str,
        params: dict[str, Any] | None = None,
    ) -> PolicyResult:
        return PolicyResult(Decision.DENY, action, level, reason, params or {}, action, code)


def _short(exc: ValidationError) -> str:
    errors = exc.errors()
    if not errors:
        return "invalid parameters"
    first = errors[0]
    loc = ".".join(str(x) for x in first.get("loc", ()))
    return f"invalid parameters: {loc}: {first.get('msg', '')}"
