from __future__ import annotations

import asyncio
import contextlib
import uuid
from typing import Annotated, Any

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Path,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from sqlalchemy import func, select, text
from starlette.responses import JSONResponse

from jarvis import __version__
from jarvis.api import schemas as s
from jarvis.api.security import authenticate_websocket
from jarvis.app_state import Services
from jarvis.audit import log as audit
from jarvis.db.models import Approval, AuditEntry, Job, Task
from jarvis.security.agents import AgentAlreadyActive, InvalidAgentId
from jarvis.security.approvals import ApprovalError, ApprovalErrorCode
from jarvis.security.policy import ACTIONS
from jarvis.security.principal import Principal
from jarvis.tasks.service import ActionDenied

router = APIRouter(prefix="/api/v1")

_DENY_STATUS = {"emergency_stop_active": 423, "unknown_action": 404, "concurrency_limit": 429}
_APPROVAL_STATUS = {
    ApprovalErrorCode.NOT_FOUND: 404,
    ApprovalErrorCode.FORBIDDEN: 403,
    ApprovalErrorCode.NOT_PENDING: 409,
    ApprovalErrorCode.EXPIRED: 410,
    ApprovalErrorCode.MISMATCH: 403,
    ApprovalErrorCode.NOT_APPROVED: 403,
    ApprovalErrorCode.CONSUMED: 409,
    ApprovalErrorCode.WRONG_REQUESTER: 403,
}
_APPROVAL_BY_VALUE = {code.value: status for code, status in _APPROVAL_STATUS.items()}


def services(request: Request) -> Services:
    svc: Services = request.app.state.services
    return svc


def principal(request: Request) -> Principal:
    p: Principal = request.state.principal
    return p


def human(request: Request) -> Principal:
    """Defence in depth: the auth middleware already keeps agents off these routes."""
    p = principal(request)
    if not p.is_human:
        raise HTTPException(403, "this endpoint requires the human operator")
    return p


Svc = Annotated[Services, Depends(services)]
Who = Annotated[Principal, Depends(principal)]
Human = Annotated[Principal, Depends(human)]


def _err(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse({"error": {"code": code, "message": message}}, status_code=status)


def _approval_out(a: Approval) -> s.ApprovalOut:
    return s.ApprovalOut.model_validate(a, from_attributes=True)


def _job_out(j: Job) -> s.JobOut:
    return s.JobOut.model_validate(j, from_attributes=True)


# ----------------------------------------------------------------- health
@router.get("/health/live")
async def live() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/health", response_model=s.HealthOut)
async def health(svc: Svc) -> s.HealthOut:
    checks: list[s.HealthCheck] = []
    try:
        async with svc.maker() as session:
            await session.execute(text("SELECT 1"))
            current = (
                await session.execute(text("SELECT version_num FROM alembic_version"))
            ).scalar_one_or_none()
        checks.append(s.HealthCheck(name="database", ok=True, detail="reachable"))
        ok = current == svc.migration_head
        checks.append(
            s.HealthCheck(
                name="migrations",
                ok=ok,
                detail=f"at {current}" + ("" if ok else f", expected {svc.migration_head}"),
            )
        )
        checks.append(await _audit_protection(svc))
    except Exception as exc:  # noqa: BLE001
        checks.append(s.HealthCheck(name="database", ok=False, detail=type(exc).__name__))
    checks.append(
        s.HealthCheck(name="event_bus", ok=True, detail=f"{svc.bus.subscriber_count} subscribers")
    )
    checks.append(
        s.HealthCheck(
            name="emergency_stop",
            ok=not svc.latch.latched,
            detail="latched: execution blocked" if svc.latch.latched else "clear",
        )
    )
    checks.append(
        s.HealthCheck(
            name="workspaces",
            ok=bool(svc.settings.workspaces),
            detail=f"{len(svc.settings.workspaces)} approved",
        )
    )
    status = "ok" if all(c.ok for c in checks) else "degraded"
    return s.HealthOut(status=status, version=__version__, api_version=s.API_VERSION, checks=checks)


_ROLE_SQL = text(
    """
    SELECT r.rolsuper AS superuser,
           pg_has_role(current_user, t.tableowner, 'MEMBER') AS owns_audit
    FROM pg_roles r
    JOIN pg_tables t ON t.tablename = 'audit_log' AND t.schemaname = current_schema()
    WHERE r.rolname = current_user
    """
)


async def _audit_protection(svc: Services) -> s.HealthCheck:
    """The audit triggers only bind a role that cannot disable them (KI-002)."""
    async with svc.maker() as session:
        row = (await session.execute(_ROLE_SQL)).one_or_none()
    if row is None:
        return s.HealthCheck(name="audit_protection", ok=False, detail="audit_log not found")
    if row.superuser or row.owns_audit:
        return s.HealthCheck(
            name="audit_protection",
            ok=False,
            detail="backend connects as the database owner/superuser and could disable the "
            "audit triggers; connect as a member of jarvis_app (docs/RECOVERY_PLAN.md)",
        )
    return s.HealthCheck(
        name="audit_protection", ok=True, detail="restricted role: audit log is insert-only"
    )


# ---------------------------------------------------------------- catalog
@router.get("/catalog", response_model=s.CatalogOut)
async def catalog(svc: Svc) -> s.CatalogOut:
    return s.CatalogOut(
        actions=[
            s.ActionInfo(
                name=a.name,
                base_level=int(a.base_level),
                description=a.description,
                params_schema=a.params_model.model_json_schema(),
            )
            for a in ACTIONS.values()
        ],
        executables=[
            s.ExecutableInfo(name=r.name, level=r.level, description=r.description)
            for r in svc.policy.allowlist.rules.values()
        ],
        workspaces=[w.name for w in svc.settings.workspaces],
    )


# ---------------------------------------------------------------- actions
@router.post(
    "/actions",
    response_model=s.ActionResponse,
    responses={403: {"model": s.ErrorOut}, 423: {"model": s.ErrorOut}},
)
async def submit_action(body: s.ActionRequest, svc: Svc, who: Who) -> Any:
    try:
        out = await svc.actions.submit(
            who, body.action, body.params, reason=body.reason, approval_id=body.approval_id
        )
    except ActionDenied as exc:
        status = _DENY_STATUS.get(exc.code) or _APPROVAL_BY_VALUE.get(exc.code, 403)
        return _err(status, exc.code, exc.message)
    http_status = 202 if out.status in {"accepted", "approval_required"} else 200
    payload = s.ActionResponse(
        status=out.status,
        action=out.action,
        level=out.level,
        task_id=out.task_id,
        job_id=out.job_id,
        approval=_approval_out(out.approval) if out.approval else None,
        result=out.result,
    )
    return JSONResponse(payload.model_dump(mode="json"), status_code=http_status)


# -------------------------------------------------------------- approvals
@router.get("/approvals", response_model=list[s.ApprovalOut])
async def list_approvals(
    svc: Svc, status: Annotated[str | None, Query(max_length=16)] = None
) -> list[s.ApprovalOut]:
    async with svc.maker() as session:
        q = select(Approval).order_by(Approval.created_at.desc()).limit(200)
        if status:
            q = q.where(Approval.status == status)
        return [_approval_out(a) for a in (await session.scalars(q)).all()]


async def _decide(svc: Services, who: Principal, approval_id: uuid.UUID, approve: bool) -> Any:
    try:
        approval = await svc.actions.decide(who, approval_id, approve)
    except ApprovalError as exc:
        return _err(_APPROVAL_STATUS[exc.code], exc.code.value, exc.message)
    return _approval_out(approval)


@router.post("/approvals/{approval_id}/approve", response_model=s.ApprovalOut)
async def approve(approval_id: uuid.UUID, svc: Svc, who: Human) -> Any:
    return await _decide(svc, who, approval_id, True)


@router.post("/approvals/{approval_id}/deny", response_model=s.ApprovalOut)
async def deny(approval_id: uuid.UUID, svc: Svc, who: Human) -> Any:
    return await _decide(svc, who, approval_id, False)


# ------------------------------------------------------------ tasks/jobs
@router.get("/tasks", response_model=list[s.TaskOut])
async def list_tasks(svc: Svc, limit: Annotated[int, Query(ge=1, le=200)] = 50) -> list[s.TaskOut]:
    async with svc.maker() as session:
        tasks = (
            await session.scalars(select(Task).order_by(Task.created_at.desc()).limit(limit))
        ).all()
        ids = [t.id for t in tasks]
        jobs = (await session.scalars(select(Job).where(Job.task_id.in_(ids)))).all() if ids else []
    by_task: dict[uuid.UUID, list[s.JobOut]] = {}
    for j in jobs:
        by_task.setdefault(j.task_id, []).append(_job_out(j))
    return [
        s.TaskOut.model_validate(
            {
                **{c: getattr(t, c) for c in s.TaskOut.model_fields if c != "jobs"},
                "jobs": by_task.get(t.id, []),
            }
        )
        for t in tasks
    ]


@router.get("/jobs/{job_id}", response_model=s.JobOut)
async def get_job(job_id: uuid.UUID, svc: Svc) -> s.JobOut:
    async with svc.maker() as session:
        job = await session.get(Job, job_id)
    if job is None:
        raise HTTPException(404, "job not found")
    return _job_out(job)


@router.post("/jobs/{job_id}/cancel")
async def cancel_job(job_id: uuid.UUID, svc: Svc, who: Who) -> dict[str, Any]:
    outcome = await svc.actions.cancel_job(who, job_id)
    if outcome is None:
        return {
            "job_id": str(job_id),
            "running": False,
            "stopped": None,
            "detail": "job is not running",
        }
    return {
        "job_id": str(job_id),
        "running": True,
        "stopped": outcome.stopped,
        "detail": outcome.detail,
    }


# ----------------------------------------------------------------- system
@router.get("/system/state", response_model=s.SystemStateOut)
async def system_state(svc: Svc) -> s.SystemStateOut:
    return s.SystemStateOut(
        emergency_stop=svc.latch.latched,
        emergency_stop_at=svc.latch.latched_at,
        active_jobs=len(svc.registry.active()),
    )


@router.post("/system/emergency-stop", response_model=s.EmergencyStopReport)
async def emergency_stop(svc: Svc, who: Human) -> s.EmergencyStopReport:
    out = await svc.actions.emergency_stop(who)
    reports = [s.KillReport(pid=k.pid, stopped=k.stopped, detail=k.detail) for k in out.kills]
    return s.EmergencyStopReport(
        latched=svc.latch.latched,
        latched_at=svc.latch.latched_at,
        jobs_cancelled=out.jobs_cancelled,
        processes=reports,
        unstopped=[r for r in reports if not r.stopped],
        persisted=out.persisted,
        agent_credentials_revoked=out.agent_credentials_revoked,
    )


# ------------------------------------------------------- agent credentials
@router.get("/agents/credentials", response_model=list[s.AgentCredentialOut])
async def list_agent_credentials(svc: Svc, _: Human) -> list[s.AgentCredentialOut]:
    return [
        s.AgentCredentialOut(agent_id=c.agent_id, created_at=c.created_at)
        for c in svc.actions.agents.list()
    ]


@router.post(
    "/agents/credentials",
    response_model=s.AgentCredentialIssued,
    status_code=201,
    responses={409: {"model": s.ErrorOut}, 422: {"model": s.ErrorOut}, 423: {"model": s.ErrorOut}},
)
async def issue_agent_credential(body: s.AgentCredentialIn, svc: Svc, who: Human) -> Any:
    try:
        cred, token = await svc.actions.issue_agent_credential(who, body.agent_id)
    except InvalidAgentId as exc:
        return _err(422, "invalid_agent_id", str(exc))
    except AgentAlreadyActive as exc:
        return _err(409, "agent_already_active", str(exc))
    except ActionDenied as exc:
        return _err(_DENY_STATUS.get(exc.code, 403), exc.code, exc.message)
    out = s.AgentCredentialIssued(agent_id=cred.agent_id, created_at=cred.created_at, token=token)
    return JSONResponse(out.model_dump(mode="json"), status_code=201)


@router.post("/agents/credentials/{agent_id}/revoke")
async def revoke_agent_credential(
    agent_id: Annotated[str, Path(max_length=64)], svc: Svc, who: Human
) -> dict[str, Any]:
    revoked = await svc.actions.revoke_agent_credential(who, agent_id)
    return {"agent_id": agent_id, "revoked": revoked}


# ------------------------------------------------------------------ audit
@router.get("/audit", response_model=list[s.AuditEntryOut])
async def list_audit(
    svc: Svc, limit: Annotated[int, Query(ge=1, le=500)] = 100
) -> list[s.AuditEntryOut]:
    async with svc.maker() as session:
        rows = (
            await session.scalars(select(AuditEntry).order_by(AuditEntry.id.desc()).limit(limit))
        ).all()
    return [s.AuditEntryOut.model_validate(r, from_attributes=True) for r in rows]


@router.get("/audit/verify", response_model=s.AuditVerifyOut)
async def verify_audit(svc: Svc) -> s.AuditVerifyOut:
    async with svc.maker() as session:
        res = await audit.verify(session)
        anchored = await svc.anchor.check(session)
    ok = res.ok and anchored.ok
    detail = res.detail if not res.ok else f"{res.detail}; {anchored.detail}"
    return s.AuditVerifyOut(
        ok=ok,
        checked=res.checked,
        first_bad_id=res.first_bad_id,
        detail=detail,
        anchored_id=anchored.anchored_id,
    )


@router.get("/audit/count")
async def audit_count(svc: Svc) -> dict[str, int]:
    async with svc.maker() as session:
        n = (await session.execute(select(func.count()).select_from(AuditEntry))).scalar_one()
    return {"count": int(n)}


# ----------------------------------------------------------------- events
@router.get("/events", response_model=list[s.EventOut])
async def list_events(
    svc: Svc,
    since_seq: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> list[s.EventOut]:
    return await svc.bus.replay(since_seq, limit)


@router.websocket("/ws")
async def events_ws(ws: WebSocket, since_seq: int | None = None) -> None:
    svc: Services = ws.app.state.services
    protocol = authenticate_websocket(
        ws, svc.settings.session_token.get_secret_value(), svc.settings.allowed_origins
    )
    if protocol is None:
        await ws.close(code=4401)
        return
    await ws.accept(subprotocol=protocol)
    sub = svc.bus.subscribe()  # subscribe before replay so nothing falls in the gap
    try:
        last = -1
        if since_seq is not None:
            for ev in await svc.bus.replay(since_seq, limit=500):
                await ws.send_text(ev.model_dump_json())
                last = ev.seq
        while True:
            getter = asyncio.ensure_future(sub.queue.get())
            receiver = asyncio.ensure_future(ws.receive_text())
            done, _ = await asyncio.wait({getter, receiver}, return_when=asyncio.FIRST_COMPLETED)
            if receiver in done:
                getter.cancel()
                receiver.result()  # raises WebSocketDisconnect on close; client msgs ignored
                continue
            receiver.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await receiver
            event = getter.result()
            if event is None:
                break
            if event.seq <= last:
                continue  # already delivered during replay
            await ws.send_text(event.model_dump_json())
            last = event.seq
    except WebSocketDisconnect:
        pass
    finally:
        svc.bus.unsubscribe(sub)
        if sub.lagged:
            with contextlib.suppress(Exception):
                await ws.close(code=4408)
