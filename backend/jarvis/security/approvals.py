"""Human approvals bound to an exact action + parameter hash. Single use, expiring."""

from __future__ import annotations

import uuid
from datetime import timedelta
from enum import StrEnum

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from jarvis.core.redaction import redact
from jarvis.core.time import utcnow
from jarvis.db.models import Approval
from jarvis.security.hashing import action_hash
from jarvis.security.policy import PolicyResult
from jarvis.security.principal import Principal


class ApprovalErrorCode(StrEnum):
    NOT_FOUND = "approval_not_found"
    FORBIDDEN = "approver_not_human"
    NOT_PENDING = "approval_not_pending"
    EXPIRED = "approval_expired"
    MISMATCH = "approval_action_mismatch"
    NOT_APPROVED = "approval_not_approved"
    CONSUMED = "approval_already_used"
    WRONG_REQUESTER = "approval_requester_mismatch"


class ApprovalError(Exception):
    def __init__(self, code: ApprovalErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


async def create(
    session: AsyncSession,
    *,
    requester: Principal,
    result: PolicyResult,
    reason: str,
    ttl_seconds: int,
) -> Approval:
    assert result.level is not None
    approval = Approval(
        id=uuid.uuid4(),
        action=result.action,
        params=result.params,
        params_hash=action_hash(result.action, result.params),
        level=int(result.level),
        target=redact(result.target),
        reason=redact(reason) or "(no reason given)",
        requester_kind=requester.kind.value,
        requester_id=requester.id,
        status="pending",
        expires_at=utcnow() + timedelta(seconds=ttl_seconds),
    )
    session.add(approval)
    await session.flush()
    return approval


async def decide(
    session: AsyncSession, *, approver: Principal, approval_id: uuid.UUID, approve: bool
) -> Approval:
    # Only an authenticated human may approve. Agents and the system can never approve,
    # including their own requests.
    if not approver.is_human:
        raise ApprovalError(
            ApprovalErrorCode.FORBIDDEN, "only a human operator can decide approvals"
        )
    approval = await session.get(Approval, approval_id, with_for_update=True)
    if approval is None:
        raise ApprovalError(ApprovalErrorCode.NOT_FOUND, "approval not found")
    if approval.status != "pending":
        raise ApprovalError(ApprovalErrorCode.NOT_PENDING, f"approval is {approval.status}")
    now = utcnow()
    if approval.expires_at <= now:
        approval.status = "expired"
        await session.flush()
        raise ApprovalError(ApprovalErrorCode.EXPIRED, "approval has expired")
    approval.status = "approved" if approve else "denied"
    approval.approver_id = approver.id
    approval.decided_at = now
    await session.flush()
    return approval


async def consume(
    session: AsyncSession, *, approval_id: uuid.UUID, result: PolicyResult, requester: Principal
) -> Approval:
    """Atomically mark an approval used, only if it matches this exact action and params and
    is presented by the principal that requested it (one agent cannot spend another's)."""
    expected = action_hash(result.action, result.params)
    now = utcnow()
    row = (
        await session.execute(
            update(Approval)
            .where(
                Approval.id == approval_id,
                Approval.status == "approved",
                Approval.consumed_at.is_(None),
                Approval.expires_at > now,
                Approval.action == result.action,
                Approval.params_hash == expected,
                Approval.requester_kind == requester.kind.value,
                Approval.requester_id == requester.id,
            )
            .values(status="consumed", consumed_at=now)
            .returning(Approval)
        )
    ).scalar_one_or_none()
    if row is not None:
        return row

    existing = (
        await session.execute(select(Approval).where(Approval.id == approval_id))
    ).scalar_one_or_none()
    if existing is None:
        raise ApprovalError(ApprovalErrorCode.NOT_FOUND, "approval not found")
    if existing.status == "consumed":
        raise ApprovalError(ApprovalErrorCode.CONSUMED, "approval has already been used")
    if existing.status != "approved":
        raise ApprovalError(ApprovalErrorCode.NOT_APPROVED, f"approval is {existing.status}")
    if existing.expires_at <= now:
        raise ApprovalError(ApprovalErrorCode.EXPIRED, "approval has expired")
    if (existing.requester_kind, existing.requester_id) != (requester.kind.value, requester.id):
        raise ApprovalError(
            ApprovalErrorCode.WRONG_REQUESTER,
            "approval was requested by a different principal and can only be used by it",
        )
    raise ApprovalError(
        ApprovalErrorCode.MISMATCH,
        "approval was granted for a different action or different parameters",
    )
