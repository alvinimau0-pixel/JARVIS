"""Who is asking. Security decisions are made on the principal, never on request content."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class PrincipalKind(StrEnum):
    HUMAN = "human"  # the operator, authenticated through the desktop session token
    AGENT = "agent"  # Claude Code / Codex / model-driven workers (Phase 6+)
    SYSTEM = "system"  # JARVIS internals (startup recovery, emergency stop handler)


@dataclass(frozen=True, slots=True)
class Principal:
    kind: PrincipalKind
    id: str

    @classmethod
    def operator(cls) -> Principal:
        return cls(PrincipalKind.HUMAN, "operator")

    @classmethod
    def agent(cls, agent_id: str) -> Principal:
        return cls(PrincipalKind.AGENT, agent_id)

    @classmethod
    def system(cls) -> Principal:
        return cls(PrincipalKind.SYSTEM, "jarvis")

    @property
    def is_human(self) -> bool:
        return self.kind is PrincipalKind.HUMAN
