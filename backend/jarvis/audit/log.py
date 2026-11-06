"""Append-only, keyed hash-chained audit log.

Each entry's hash is an HMAC-SHA256, under a secret audit key, over the previous entry's hash
and its own canonical content. Any modification, deletion or reordering breaks verification,
and without the key nobody (including someone with full database access) can recompute a
valid chain. The key lives in the OS credential store, never in the database.

Defence in layers:
- the database rejects UPDATE/DELETE/TRUNCATE with triggers (migration 0001);
- the runtime role ``jarvis_app`` may only SELECT and INSERT audit rows and does not own the
  table, so it cannot disable or drop those triggers (migration 0002);
- the chain head is exported to an anchor file outside the database (``anchor.py``), so
  removing entries from the end of the chain is detected too.
"""

from __future__ import annotations

import hashlib
import hmac
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
_MIN_KEY_LEN = 32
_key: bytes | None = None


class AuditKeyMissing(RuntimeError):
    pass


def set_key(key: str) -> None:
    """Configure the audit HMAC key for this process (done once, by ``create_app``)."""
    global _key
    if len(key) < _MIN_KEY_LEN:
        raise ValueError(f"audit key must be at least {_MIN_KEY_LEN} characters")
    _key = key.encode("utf-8")


def _require_key() -> bytes:
    if _key is None:  # fail closed: an unkeyed chain could be forged
        raise AuditKeyMissing("audit key is not configured")
    return _key


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
    return hmac.new(_require_key(), body.encode("utf-8"), hashlib.sha256).hexdigest()


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
        if not hmac.compare_digest(entry.hash, expected):
            return VerifyResult(
                False,
                checked,
                entry.id,
                "entry content does not match its keyed hash (tampered, or the audit key changed)",
            )
        prev = entry.hash
        checked += 1
    return VerifyResult(True, checked, None, "chain intact")
