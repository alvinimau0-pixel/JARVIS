"""Action lifecycle: policy -> (approval) -> task/job -> controlled execution -> events + audit.

This is the single path by which anything gets executed. There is no endpoint that runs a raw
command; everything is an action evaluated by the PolicyEngine.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from jarvis.api.schemas import EventType
from jarvis.audit import log as audit
from jarvis.core.redaction import redact_text
from jarvis.core.time import utcnow
from jarvis.db.models import Approval, Job, Task
from jarvis.events.bus import EventBus
from jarvis.exec.proctree import KillOutcome
from jarvis.exec.runner import ProcessRegistry, run_controlled
from jarvis.security import approvals
from jarvis.security.agents import AgentCredential, AgentCredentials
from jarvis.security.emergency import EmergencyLatch
from jarvis.security.policy import Decision, DenyCode, ExecPlan, PolicyEngine, PolicyResult
from jarvis.security.principal import Principal

log = logging.getLogger(__name__)


class ActionDenied(Exception):
    def __init__(self, code: str, message: str, level: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.level = level


@dataclass
class SubmitOutcome:
    status: str  # accepted | approval_required | completed
    action: str
    level: int
    task_id: uuid.UUID | None = None
    job_id: uuid.UUID | None = None
    approval: Approval | None = None
    result: dict[str, Any] | None = None


@dataclass
class StopOutcome:
    jobs_cancelled: int
    kills: list[KillOutcome] = field(default_factory=list)
    persisted: bool = True
    agent_credentials_revoked: int = 0


class ActionService:
    def __init__(
        self,
        *,
        maker: async_sessionmaker[AsyncSession],
        bus: EventBus,
        policy: PolicyEngine,
        registry: ProcessRegistry,
        latch: EmergencyLatch,
        approval_ttl_seconds: int,
        output_limit: int,
        max_concurrent_jobs: int = 4,
        agents: AgentCredentials | None = None,
    ) -> None:
        self.maker = maker
        self.bus = bus
        self.policy = policy
        self.registry = registry
        self.latch = latch
        self.approval_ttl_seconds = approval_ttl_seconds
        self.output_limit = output_limit
        self.max_concurrent_jobs = max_concurrent_jobs
        self.agents = agents or AgentCredentials()
        self._bg: set[asyncio.Task[None]] = set()
        self._cancel_requested: set[uuid.UUID] = set()

    # ------------------------------------------------------------------ submit
    async def submit(
        self,
        principal: Principal,
        action: str,
        params: dict[str, Any],
        *,
        reason: str = "",
        approval_id: uuid.UUID | None = None,
    ) -> SubmitOutcome:
        result = self.policy.evaluate(
            principal, action, params, emergency_latched=self.latch.latched
        )

        if result.decision is Decision.DENY:
            await self._record_denial(principal, result)
            raise ActionDenied(
                (result.code or DenyCode.INVALID_PARAMS).value,
                result.reason,
                int(result.level) if result.level is not None else None,
            )

        assert result.level is not None
        level = int(result.level)
        consumed: Approval | None = None

        if result.decision is Decision.REQUIRE_APPROVAL:
            if approval_id is None:
                return await self._request_approval(principal, result, reason)
            failure: approvals.ApprovalError | None = None
            try:
                async with self.maker() as session, session.begin():
                    consumed = await approvals.consume(
                        session, approval_id=approval_id, result=result, requester=principal
                    )
            except approvals.ApprovalError as exc:
                failure = exc
            if failure is not None:
                # Audit in its own transaction: the consume transaction was rolled back.
                await self._audit_standalone(
                    principal,
                    action=result.action,
                    target=result.target,
                    level=level,
                    decision="denied",
                    details={
                        "code": failure.code.value,
                        "reason": failure.message,
                        "approval_id": str(approval_id),
                    },
                )
                raise ActionDenied(failure.code.value, failure.message, level) from failure

        if result.action == "system.emergency_reset":
            return await self._emergency_reset(principal, result, consumed)

        assert result.plan is not None
        if len(self._bg) >= self.max_concurrent_jobs:
            await self._audit_standalone(
                principal,
                action=result.action,
                target=result.target,
                level=level,
                decision="denied",
                details={"code": "concurrency_limit", "running": len(self._bg)},
            )
            raise ActionDenied(
                "concurrency_limit",
                f"{len(self._bg)} jobs already running (limit {self.max_concurrent_jobs})",
                level,
            )
        return await self._start_exec(principal, result, result.plan, consumed)

    async def _audit_standalone(self, principal: Principal, **entry: Any) -> None:
        async with self.maker() as session, session.begin():
            await audit.append(session, actor=principal, **entry)

    async def _record_denial(self, principal: Principal, result: PolicyResult) -> None:
        level = int(result.level) if result.level is not None else None
        async with self.maker() as session, session.begin():
            await audit.append(
                session,
                actor=principal,
                action=result.action,
                target=result.target,
                level=level,
                decision="denied",
                details={
                    "code": result.code.value if result.code else None,
                    "reason": result.reason,
                    "params": result.params,
                },
            )
        await self.bus.publish(
            EventType.ACTION_DENIED,
            source="policy",
            payload={
                "action": result.action,
                "level": level,
                "code": result.code.value if result.code else None,
                "reason": result.reason,
            },
        )

    async def _request_approval(
        self, principal: Principal, result: PolicyResult, reason: str
    ) -> SubmitOutcome:
        assert result.level is not None
        async with self.maker() as session, session.begin():
            approval = await approvals.create(
                session,
                requester=principal,
                result=result,
                reason=reason,
                ttl_seconds=self.approval_ttl_seconds,
            )
            await audit.append(
                session,
                actor=principal,
                action=result.action,
                target=result.target,
                level=int(result.level),
                decision="approval_requested",
                details={"approval_id": str(approval.id), "params_hash": approval.params_hash},
            )
        await self.bus.publish(
            EventType.APPROVAL_REQUIRED,
            source="policy",
            payload={
                "approval_id": str(approval.id),
                "action": approval.action,
                "level": approval.level,
                "target": approval.target,
            },
        )
        return SubmitOutcome(
            "approval_required", result.action, int(result.level), approval=approval
        )

    # ------------------------------------------------------------ approvals
    async def decide(self, principal: Principal, approval_id: uuid.UUID, approve: bool) -> Approval:
        try:
            async with self.maker() as session, session.begin():
                approval = await approvals.decide(
                    session, approver=principal, approval_id=approval_id, approve=approve
                )
                await audit.append(
                    session,
                    actor=principal,
                    action="approval.decide",
                    target=str(approval_id),
                    level=approval.level,
                    decision="approved" if approve else "rejected",
                    details={"action": approval.action, "params_hash": approval.params_hash},
                )
        except approvals.ApprovalError as exc:
            await self._audit_standalone(
                principal,
                action="approval.decide",
                target=str(approval_id),
                decision="denied",
                details={"code": exc.code.value, "reason": exc.message},
            )
            raise
        await self.bus.publish(
            EventType.APPROVAL_GRANTED if approve else EventType.APPROVAL_DENIED,
            source="operator",
            payload={
                "approval_id": str(approval.id),
                "action": approval.action,
                "level": approval.level,
            },
        )
        return approval

    # ---------------------------------------------------------------- exec
    async def _start_exec(
        self,
        principal: Principal,
        result: PolicyResult,
        plan: ExecPlan,
        approval: Approval | None,
    ) -> SubmitOutcome:
        assert result.level is not None
        level = int(result.level)
        task_id, job_id = uuid.uuid4(), uuid.uuid4()
        async with self.maker() as session, session.begin():
            session.add(
                Task(
                    id=task_id,
                    title=result.target[:500],
                    status="running",
                    created_by_kind=principal.kind.value,
                    created_by_id=principal.id,
                )
            )
            await session.flush()
            session.add(
                Job(
                    id=job_id,
                    task_id=task_id,
                    action=result.action,
                    owner="exec",
                    status="queued",
                    approval_id=approval.id if approval else None,
                )
            )
            await audit.append(
                session,
                actor=principal,
                action=result.action,
                target=result.target,
                level=level,
                decision="approved_execution" if approval else "allowed",
                details={
                    "task_id": str(task_id),
                    "job_id": str(job_id),
                    "approval_id": str(approval.id) if approval else None,
                    "executable": plan.rule.name,
                    "cwd": str(plan.cwd),
                },
            )
        await self.bus.publish(
            EventType.TASK_CREATED,
            source="orchestrator",
            task_id=task_id,
            job_id=job_id,
            payload={"title": result.target, "action": result.action, "level": level},
        )
        bg = asyncio.create_task(self._run_job(principal, task_id, job_id, plan, level, approval))
        self._bg.add(bg)
        bg.add_done_callback(self._bg.discard)
        return SubmitOutcome("accepted", result.action, level, task_id=task_id, job_id=job_id)

    async def _run_job(
        self,
        principal: Principal,
        task_id: uuid.UUID,
        job_id: uuid.UUID,
        plan: ExecPlan,
        level: int,
        approval: Approval | None,
    ) -> None:
        if job_id in self._cancel_requested or self.latch.latched:
            await self._finish(
                principal,
                task_id,
                job_id,
                "cancelled",
                level,
                approval,
                error="cancelled before start",
            )
            return

        async def on_started(pid: int) -> None:
            async with self.maker() as session, session.begin():
                await session.execute(
                    update(Job)
                    .where(Job.id == job_id)
                    .values(status="running", pid=pid, started_at=utcnow())
                )
            await self.bus.publish(
                EventType.JOB_STARTED,
                source="exec",
                task_id=task_id,
                job_id=job_id,
                payload={"pid": pid, "executable": plan.rule.name, "level": level},
            )

        try:
            res = await run_controlled(
                rule=plan.rule,
                argv_tail=plan.argv_tail,
                cwd=plan.cwd,
                timeout_s=plan.timeout_s,
                output_limit=self.output_limit,
                registry=self.registry,
                job_id=job_id,
                on_started=on_started,
                should_abort=lambda: job_id in self._cancel_requested or self.latch.latched,
            )
        except Exception as exc:  # noqa: BLE001 - surfaced as a failed job, never swallowed
            log.exception("job %s failed to run", job_id)
            await self._finish(
                principal,
                task_id,
                job_id,
                "failed",
                level,
                approval,
                error=redact_text(f"{type(exc).__name__}: {exc}"),
            )
            return

        if res.cancelled:
            status = "cancelled"
        elif res.timed_out:
            status = "timed_out"
        elif res.exit_code == 0:
            status = "completed"
        else:
            status = "failed"
        await self._finish(
            principal,
            task_id,
            job_id,
            status,
            level,
            approval,
            exit_code=res.exit_code,
            stdout=res.stdout,
            stderr=res.stderr,
            truncated=res.truncated,
            duration_s=res.duration_s,
            kill=res.kill,
        )

    async def _finish(
        self,
        principal: Principal,
        task_id: uuid.UUID,
        job_id: uuid.UUID,
        status: str,
        level: int,
        approval: Approval | None,
        *,
        exit_code: int | None = None,
        stdout: str | None = None,
        stderr: str | None = None,
        truncated: bool = False,
        duration_s: float | None = None,
        error: str | None = None,
        kill: KillOutcome | None = None,
    ) -> None:
        task_status = {"completed": "completed", "cancelled": "cancelled"}.get(status, "failed")
        summary: dict[str, Any] = {
            "status": status,
            "exit_code": exit_code,
            "duration_s": duration_s,
            "output_truncated": truncated,
            "error": error,
            "kill": {"pid": kill.pid, "stopped": kill.stopped, "detail": kill.detail}
            if kill
            else None,
        }
        async with self.maker() as session, session.begin():
            await session.execute(
                update(Job)
                .where(Job.id == job_id)
                .values(
                    status=status,
                    exit_code=exit_code,
                    stdout=stdout,
                    stderr=stderr,
                    output_truncated=truncated,
                    error=error,
                    finished_at=utcnow(),
                )
            )
            await session.execute(update(Task).where(Task.id == task_id).values(status=task_status))
            if approval is not None:
                await session.execute(
                    update(Approval)
                    .where(Approval.id == approval.id)
                    .values(execution_result=summary)
                )
            await audit.append(
                session,
                actor=principal,
                action="job.finished",
                target=str(job_id),
                level=level,
                decision=status,
                details=summary,
            )
        self._cancel_requested.discard(job_id)
        job_event = {
            "completed": EventType.JOB_COMPLETED,
            "cancelled": EventType.JOB_CANCELLED,
        }.get(status, EventType.JOB_FAILED)
        task_event = {
            "completed": EventType.TASK_COMPLETED,
            "cancelled": EventType.TASK_CANCELLED,
        }.get(task_status, EventType.TASK_FAILED)
        await self.bus.publish(
            job_event, source="exec", task_id=task_id, job_id=job_id, payload=summary
        )
        await self.bus.publish(
            task_event, source="orchestrator", task_id=task_id, payload={"status": task_status}
        )

    # -------------------------------------------------------------- cancel
    async def cancel_job(self, principal: Principal, job_id: uuid.UUID) -> KillOutcome | None:
        self._cancel_requested.add(job_id)
        outcome = await asyncio.to_thread(self.registry.cancel, job_id)
        async with self.maker() as session, session.begin():
            await audit.append(
                session,
                actor=principal,
                action="job.cancel",
                target=str(job_id),
                decision="requested",
                details={
                    "killed": outcome.stopped if outcome else None,
                    "detail": outcome.detail if outcome else "not running",
                },
            )
        return outcome

    # ------------------------------------------------------- emergency stop
    async def emergency_stop(self, principal: Principal) -> StopOutcome:
        """Stop everything. Killing processes never waits on, or depends on, the database."""
        self.latch.engage_now()
        # No agent may keep acting after a stop; they are re-issued deliberately afterwards.
        revoked_agents = self.agents.revoke_all()
        active = self.registry.active()
        self._cancel_requested.update(active)
        kills = await asyncio.to_thread(self.registry.kill_all)
        queued: list[uuid.UUID] = []
        persisted = True
        try:
            async with self.maker() as session, session.begin():
                await self.latch.persist_engaged(session, principal.id)
                # Outstanding approvals must not survive a stop; they are re-requested later.
                expired = (
                    (
                        await session.execute(
                            update(Approval)
                            .where(Approval.status.in_(("pending", "approved")))
                            .values(status="expired")
                            .returning(Approval.id)
                        )
                    )
                    .scalars()
                    .all()
                )
                queued = list(
                    (await session.scalars(select(Job.id).where(Job.status == "queued"))).all()
                )
                self._cancel_requested.update(queued)
                await audit.append(
                    session,
                    actor=principal,
                    action="system.emergency_stop",
                    target="all",
                    level=3,
                    decision="executed",
                    details={
                        "active_jobs": [str(j) for j in active],
                        "approvals_expired": len(expired),
                        "agents_revoked": revoked_agents,
                        "kills": [
                            {"pid": k.pid, "stopped": k.stopped, "detail": k.detail} for k in kills
                        ],
                    },
                )
        except Exception:  # noqa: BLE001 - the stop itself already happened; report, don't fail
            persisted = False
            log.exception("emergency stop executed but could not be persisted/audited")
        try:
            await self.bus.publish(
                EventType.SYSTEM_EMERGENCY_STOP,
                source="operator" if principal.is_human else principal.kind.value,
                payload={
                    "jobs_cancelled": len(active) + len(queued),
                    "unstopped": [k.pid for k in kills if not k.stopped],
                    "persisted": persisted,
                },
            )
        except Exception:  # noqa: BLE001
            log.exception("emergency stop event could not be published")
        # Wait briefly for job runners to record their final status.
        pending = [t for t in self._bg if not t.done()]
        if pending:
            await asyncio.wait(pending, timeout=10)
        return StopOutcome(
            jobs_cancelled=len(active) + len(queued),
            kills=kills,
            persisted=persisted,
            agent_credentials_revoked=revoked_agents,
        )

    async def _emergency_reset(
        self, principal: Principal, result: PolicyResult, approval: Approval | None
    ) -> SubmitOutcome:
        assert approval is not None and result.level is not None
        async with self.maker() as session, session.begin():
            await self.latch.persist_release(session, principal.id)
            await audit.append(
                session,
                actor=principal,
                action=result.action,
                target="emergency_stop",
                level=int(result.level),
                decision="approved_execution",
                details={"approval_id": str(approval.id)},
            )
            await session.execute(
                update(Approval)
                .where(Approval.id == approval.id)
                .values(execution_result={"status": "completed"})
            )
        self.latch.mark_released()  # only after the release is durably committed
        await self.bus.publish(EventType.SYSTEM_EMERGENCY_RESET, source="operator", payload={})
        return SubmitOutcome(
            "completed", result.action, int(result.level), result={"emergency_stop": False}
        )

    # ------------------------------------------------------- agent credentials
    async def issue_agent_credential(
        self, principal: Principal, agent_id: str
    ) -> tuple[AgentCredential, str]:
        if not principal.is_human:  # also enforced at the transport layer
            raise PermissionError("only the human operator can issue agent credentials")
        if self.latch.latched:
            raise ActionDenied(
                "emergency_stop_active", "emergency stop is active; no agent may be started"
            )
        cred, token = self.agents.issue(agent_id)
        try:
            await self._audit_standalone(
                principal,
                action="agent.credential_issue",
                target=agent_id,
                decision="executed",
                details={"fingerprint": cred.digest[:12]},
            )
        except Exception:
            self.agents.revoke(agent_id)  # never hand out a credential that was not audited
            raise
        return cred, token

    async def revoke_agent_credential(self, principal: Principal, agent_id: str) -> bool:
        if not principal.is_human:
            raise PermissionError("only the human operator can revoke agent credentials")
        revoked = self.agents.revoke(agent_id)  # revoke first: never wait on the database
        await self._audit_standalone(
            principal,
            action="agent.credential_revoke",
            target=agent_id,
            decision="executed" if revoked else "not_found",
            details={},
        )
        return revoked

    # ------------------------------------------------------------ recovery
    async def recover_after_restart(self) -> None:
        """Jobs marked running/queued from a previous process cannot still be ours."""
        async with self.maker() as session, session.begin():
            stale = (
                await session.scalars(select(Job).where(Job.status.in_(("queued", "running"))))
            ).all()
            orphan_pids = [j.pid for j in stale if j.pid]
            for job in stale:
                job.status = "failed"
                job.error = "backend restarted while job was active; outcome unknown"
                job.finished_at = utcnow()
                await session.execute(
                    update(Task).where(Task.id == job.task_id).values(status="failed")
                )
            if stale:
                await audit.append(
                    session,
                    actor=Principal.system(),
                    action="system.recover",
                    target="jobs",
                    decision="marked_failed",
                    details={"jobs": [str(j.id) for j in stale], "unverified_pids": orphan_pids},
                )
        await self.bus.publish(
            EventType.SYSTEM_RECOVERED,
            source="system",
            payload={
                "stale_jobs_failed": len(stale),
                "unverified_pids": orphan_pids,
                "emergency_stop": self.latch.latched,
            },
        )

    async def shutdown(self) -> None:
        await asyncio.to_thread(self.registry.kill_all)
        if self._bg:
            await asyncio.wait(list(self._bg), timeout=10)
