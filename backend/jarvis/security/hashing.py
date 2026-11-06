"""Canonical hashing that binds an approval to one exact action and parameter set."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def action_hash(action: str, params: dict[str, Any]) -> str:
    payload = canonical_json({"action": action, "params": params})
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
