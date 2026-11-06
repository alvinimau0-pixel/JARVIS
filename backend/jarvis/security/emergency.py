"""Global emergency-stop latch, persisted so it survives a backend restart."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from jarvis.core.time import utcnow
from jarvis.db.models import SystemState

_KEY = "emergency_stop"


class EmergencyLatch:
    def __init__(self, maker: async_sessionmaker[AsyncSession]) -> None:
        self._maker = maker
        self.latched = False
        self.latched_at: datetime | None = None

    async def load(self) -> None:
        async with self._maker() as session:
            row = await session.get(SystemState, _KEY)
        if row is not None:
            self.latched = bool(row.value.get("latched"))
            at = row.value.get("at")
            self.latched_at = datetime.fromisoformat(at) if at else None

    def engage_now(self) -> None:
        """Block execution immediately, in memory. Must not depend on the database."""
        self.latched = True
        self.latched_at = utcnow()

    async def persist_engaged(self, session: AsyncSession, by: str) -> None:
        await self._persist(session, True, self.latched_at or utcnow(), by)

    async def persist_release(self, session: AsyncSession, by: str) -> None:
        """Persist the release only. Call mark_released() after the transaction commits, so a
        failed commit can never leave execution unblocked while the database says latched."""
        await self._persist(session, False, None, by)

    def mark_released(self) -> None:
        self.latched = False
        self.latched_at = None

    async def _persist(
        self, session: AsyncSession, latched: bool, at: datetime | None, by: str
    ) -> None:
        value: dict[str, Any] = {
            "latched": latched,
            "at": at.isoformat() if at else None,
            "by": by,
        }
        stmt = insert(SystemState).values(key=_KEY, value=value)
        stmt = stmt.on_conflict_do_update(index_elements=[SystemState.key], set_={"value": value})
        await session.execute(stmt)
