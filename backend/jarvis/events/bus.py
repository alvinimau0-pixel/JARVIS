"""Persisted, ordered event stream.

Every event is written to the ``events`` table first (giving it a monotonically increasing
``seq``), then broadcast to live subscribers. Clients that miss events reconnect with
``since_seq`` and replay from the database, so the UI never has to guess task state.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from jarvis.api.schemas import EventOut, EventType
from jarvis.core.redaction import redact
from jarvis.db.models import Event

log = logging.getLogger(__name__)

SUBSCRIBER_QUEUE_SIZE = 1000


class Subscriber:
    def __init__(self) -> None:
        self.queue: asyncio.Queue[EventOut | None] = asyncio.Queue(SUBSCRIBER_QUEUE_SIZE)
        self.lagged = False


class EventBus:
    def __init__(self, maker: async_sessionmaker[AsyncSession]) -> None:
        self._maker = maker
        self._subs: set[Subscriber] = set()
        self._lock = asyncio.Lock()

    @property
    def subscriber_count(self) -> int:
        return len(self._subs)

    def subscribe(self) -> Subscriber:
        sub = Subscriber()
        self._subs.add(sub)
        return sub

    def unsubscribe(self, sub: Subscriber) -> None:
        self._subs.discard(sub)

    async def publish(
        self,
        type_: EventType,
        *,
        source: str,
        task_id: uuid.UUID | None = None,
        job_id: uuid.UUID | None = None,
        payload: dict[str, Any] | None = None,
    ) -> EventOut:
        async with self._lock:  # serialise so broadcast order == seq order
            async with self._maker() as session, session.begin():
                row = Event(
                    id=uuid.uuid4(),
                    type=type_.value,
                    source=source,
                    task_id=task_id,
                    job_id=job_id,
                    payload=redact(payload or {}),
                )
                session.add(row)
                await session.flush()
                await session.refresh(row)
                event = to_out(row)
            for sub in list(self._subs):
                try:
                    sub.queue.put_nowait(event)
                except asyncio.QueueFull:
                    # Slow consumer: disconnect it; it will reconnect and replay via since_seq.
                    sub.lagged = True
                    self._subs.discard(sub)
                    log.warning("event subscriber lagged; disconnecting")
            return event

    async def replay(self, since_seq: int, limit: int = 500) -> list[EventOut]:
        async with self._maker() as session:
            rows = (
                await session.scalars(
                    select(Event).where(Event.seq > since_seq).order_by(Event.seq).limit(limit)
                )
            ).all()
            return [to_out(r) for r in rows]


def to_out(row: Event) -> EventOut:
    return EventOut(
        id=row.id,
        seq=row.seq,
        type=EventType(row.type),
        source=row.source,
        task_id=row.task_id,
        job_id=row.job_id,
        ts=row.ts,
        payload=row.payload,
    )
