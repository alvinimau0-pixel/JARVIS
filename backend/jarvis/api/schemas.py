"""Versioned API and event contracts (v1). TypeScript types are generated from these.

Changing a model here changes the public contract: update docs/API_CONTRACTS.md and run
``pnpm contracts:gen``. CI fails if the generated TypeScript drifts.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

API_VERSION = "v1"


class EventType(StrEnum):
    TASK_CREATED = "task.created"
    TASK_COMPLETED = "task.completed"
    TASK_FAILED = "task.failed"
    TASK_CANCELLED = "task.cancelled"
    JOB_STARTED = "job.started"
    JOB_COMPLETED = "job.completed"
    JOB_FAILED = "job.failed"
    JOB_CANCELLED = "job.cancelled"
    APPROVAL_REQUIRED = "approval.required"
    APPROVAL_GRANTED = "approval.granted"
    APPROVAL_DENIED = "approval.denied"
    ACTION_DENIED = "action.denied"
    SYSTEM_EMERGENCY_STOP = "system.emergency_stop"
    SYSTEM_EMERGENCY_RESET = "system.emergency_reset"
    SYSTEM_RECOVERED = "system.recovered"


class EventOut(BaseModel):
    id: uuid.UUID
    seq: int = Field(description="Monotonic per-backend sequence number; use for ordering/dedupe")
    type: EventType
    source: str
    task_id: uuid.UUID | None = None
    job_id: uuid.UUID | None = None
    ts: datetime
    payload: dict[str, Any]


class ErrorBody(BaseModel):
    code: str
    message: str


class ErrorOut(BaseModel):
    error: ErrorBody


class ActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = Field(min_length=1, max_length=128)
    params: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(default="", max_length=2000)
    approval_id: uuid.UUID | None = None


class ApprovalOut(BaseModel):
    id: uuid.UUID
    action: str
    params: dict[str, Any]
    params_hash: str
    level: int
    target: str
    reason: str
    requester_kind: str
    requester_id: str
    status: Literal["pending", "approved", "denied", "expired", "consumed"]
    approver_id: str | None
    created_at: datetime
    expires_at: datetime
    decided_at: datetime | None
    consumed_at: datetime | None
    execution_result: dict[str, Any] | None


class ActionResponse(BaseModel):
    status: Literal["accepted", "approval_required", "completed"]
    action: str
    level: int
    task_id: uuid.UUID | None = None
    job_id: uuid.UUID | None = None
    approval: ApprovalOut | None = None
    result: dict[str, Any] | None = None


class JobOut(BaseModel):
    id: uuid.UUID
    task_id: uuid.UUID
    action: str
    owner: str
    status: Literal["queued", "running", "completed", "failed", "cancelled", "timed_out"]
    approval_id: uuid.UUID | None
    pid: int | None
    exit_code: int | None
    stdout: str | None
    stderr: str | None
    output_truncated: bool
    error: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class TaskOut(BaseModel):
    id: uuid.UUID
    title: str
    status: Literal["pending", "running", "waiting_approval", "completed", "failed", "cancelled"]
    created_by_kind: str
    created_by_id: str
    created_at: datetime
    updated_at: datetime
    jobs: list[JobOut]


class ExecutableInfo(BaseModel):
    name: str
    level: int
    description: str


class ActionInfo(BaseModel):
    name: str
    base_level: int
    description: str
    params_schema: dict[str, Any]


class CatalogOut(BaseModel):
    actions: list[ActionInfo]
    executables: list[ExecutableInfo]
    workspaces: list[str]


class KillReport(BaseModel):
    pid: int
    stopped: bool
    detail: str


class EmergencyStopReport(BaseModel):
    latched: bool
    latched_at: datetime | None
    jobs_cancelled: int
    processes: list[KillReport]
    unstopped: list[KillReport] = Field(
        description="Processes that could not be confirmed stopped. Empty means all stopped."
    )
    persisted: bool = Field(
        description="False if the stop worked but could not be saved/audited (e.g. DB down). "
        "In that case the latch is active only until the backend restarts."
    )


class SystemStateOut(BaseModel):
    emergency_stop: bool
    emergency_stop_at: datetime | None
    active_jobs: int


class HealthCheck(BaseModel):
    name: str
    ok: bool
    detail: str


class HealthOut(BaseModel):
    status: Literal["ok", "degraded"]
    version: str
    api_version: str
    checks: list[HealthCheck]


class AuditEntryOut(BaseModel):
    id: int
    ts: datetime
    actor_kind: str
    actor_id: str
    action: str
    target: str
    level: int | None
    decision: str
    details: dict[str, Any]
    hash: str


class AuditVerifyOut(BaseModel):
    ok: bool
    checked: int
    first_bad_id: int | None
    detail: str
