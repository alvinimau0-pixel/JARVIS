"""External anchor for the audit chain: detects entries removed from the end of the log.

A keyed hash chain stops anyone without the key from forging or editing entries, but on its
own it cannot notice that the newest entries were deleted (what remains is still a valid
chain). So the backend periodically appends the chain head ``{id, hash}`` to a file outside
the database. Verification then checks that the latest anchored entry still exists with the
same keyed hash.

Residual risk (documented in docs/SECURITY.md): someone who controls both the database owner
role and this file can still truncate undetected. Off-machine anchoring (e.g. to the paired
phone) is planned with Phase 11.
"""

from __future__ import annotations

import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jarvis.core.time import utcnow
from jarvis.db.models import AuditEntry

ANCHOR_FILENAME = "audit-anchor.jsonl"


class AnchorCorrupt(Exception):
    pass


@dataclass(frozen=True)
class Anchor:
    id: int
    hash: str


@dataclass(frozen=True)
class AnchorCheck:
    ok: bool
    anchored_id: int | None
    detail: str


class AuditAnchor:
    def __init__(self, path: Path) -> None:
        self.path = path

    def latest(self) -> Anchor | None:
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return None
        best: Anchor | None = None
        for n, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
                anchor = Anchor(int(raw["id"]), str(raw["hash"]))
            except (ValueError, KeyError, TypeError) as exc:
                raise AnchorCorrupt(f"anchor file line {n} is unreadable") from exc
            if best is None or anchor.id > best.id:
                best = anchor
        return best

    async def record(self, session: AsyncSession) -> Anchor | None:
        """Append the current chain head if it moved since the last anchor."""
        row = (
            await session.execute(
                select(AuditEntry.id, AuditEntry.hash).order_by(AuditEntry.id.desc()).limit(1)
            )
        ).one_or_none()
        if row is None:
            return None
        head = Anchor(int(row.id), str(row.hash))
        try:
            last = self.latest()
        except AnchorCorrupt:
            last = None  # keep appending; verification reports the corruption
        if last is not None and last.id >= head.id:
            return last
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps({"id": head.id, "hash": head.hash, "ts": utcnow().isoformat()})
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (line + "\n").encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        return head

    async def check(self, session: AsyncSession) -> AnchorCheck:
        try:
            anchor = self.latest()
        except AnchorCorrupt as exc:
            return AnchorCheck(False, None, str(exc))
        if anchor is None:
            return AnchorCheck(True, None, "no anchor recorded yet")
        stored = (
            await session.execute(select(AuditEntry.hash).where(AuditEntry.id == anchor.id))
        ).scalar_one_or_none()
        if stored is None:
            return AnchorCheck(
                False,
                anchor.id,
                f"anchored entry {anchor.id} is missing: entries were removed from the log",
            )
        if not hmac.compare_digest(stored, anchor.hash):
            return AnchorCheck(
                False, anchor.id, f"anchored entry {anchor.id} was replaced: the log was rewritten"
            )
        return AnchorCheck(True, anchor.id, f"anchored through entry {anchor.id}")
