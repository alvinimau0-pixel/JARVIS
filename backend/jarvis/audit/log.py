"""Append-only, hash-chained audit log.

Each entry's hash covers the previous entry's hash and its own canonical content, so any
modification, deletion or reordering breaks verification. The database additionally rejects
UPDATE/DELETE/TRUNCATE with a trigger (migration 0001).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from jarvis.core.redaction import redact
from jarvis.core.time import utcnow
from jarvis.db.models import AuditEntry
from jarvis.security.hashing import canonical_json
from jarvis.security.principal import Principal

GENESIS_HASH = "0" * 64
_AUDIT_LOCK_KEY = 0x4A41_5256  # "JARV": serialises appends so the chain stays linear


def compute_hash(
    *,
    prev_hash: str,
    ts: datetime,
    actor_kind: str,
    actor_id: str,
    action: str,
    target: str,
    level: int | None,
    decision: str,
    details: dict[str, Any],
) -> str:
    body = canonical_json(
        {
            "prev": prev_hash,
            "ts": ts.astimezone(UTC).isoformat(),
            "actor_kind": actor_kind,
            "actor_id": actor_id,
            "action": action,
            "target": target,
            "level": level,
            "decision": decision,
            "details": details,
        }
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


async def append(
    session: AsyncSession,
    *,
    actor: Principal,
    action: str,
    target: str,
    decision: str,
    level: int | None = None,
    details: dict[str, Any] | None = None,
) -> AuditEntry:
    """Append within the caller's transaction (the action and its audit commit together)."""
    await session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _AUDIT_LOCK_KEY})
    prev = (
        await session.execute(select(AuditEntry.hash).order_by(AuditEntry.id.desc()).limit(1))
    ).scalar_one_or_none() or GENESIS_HASH
    safe_details: dict[str, Any] = redact(details or {})
    safe_target: str = redact(target)
    ts = utcnow()
    entry = AuditEntry(
        ts=ts,
        actor_kind=actor.kind.value,
        actor_id=actor.id,
        action=action,
        target=safe_target,
        level=level,
        decision=decision,
        details=safe_details,
        prev_hash=prev,
        hash=compute_hash(
            prev_hash=prev,
            ts=ts,
            actor_kind=actor.kind.value,
            actor_id=actor.id,
            action=action,
            target=safe_target,
            level=level,
            decision=decision,
            details=safe_details,
        ),
    )
    session.add(entry)
    await session.flush()
    return entry


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    checked: int
    first_bad_id: int | None
    detail: str


async def verify(session: AsyncSession) -> VerifyResult:
    prev = GENESIS_HASH
    checked = 0
    result = await session.stream_scalars(select(AuditEntry).order_by(AuditEntry.id))
    async for entry in result:
        expected = compute_hash(
            prev_hash=prev,
            ts=entry.ts,
            actor_kind=entry.actor_kind,
            actor_id=entry.actor_id,
            action=entry.action,
            target=entry.target,
            level=entry.level,
            decision=entry.decision,
            details=entry.details,
        )
        if entry.prev_hash != prev:
            return VerifyResult(False, checked, entry.id, "chain link broken (prev_hash mismatch)")
        if entry.hash != expected:
            return VerifyResult(False, checked, entry.id, "entry content does not match its hash")
        prev = entry.hash
        checked += 1
    return VerifyResult(True, checked, None, "chain intact")
