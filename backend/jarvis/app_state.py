from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from jarvis.core.config import Settings
from jarvis.events.bus import EventBus
from jarvis.exec.runner import ProcessRegistry
from jarvis.security.emergency import EmergencyLatch
from jarvis.security.policy import PolicyEngine
from jarvis.tasks.service import ActionService


@dataclass
class Services:
    settings: Settings
    engine: AsyncEngine
    maker: async_sessionmaker[AsyncSession]
    bus: EventBus
    policy: PolicyEngine
    registry: ProcessRegistry
    latch: EmergencyLatch
    actions: ActionService
    migration_head: str
