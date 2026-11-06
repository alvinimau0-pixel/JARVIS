"""Export the OpenAPI contract to packages/contracts/openapi.json (source of truth: Pydantic)."""

from __future__ import annotations

import json
import secrets
from pathlib import Path

from jarvis.core.config import Settings
from jarvis.main import create_app

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "packages" / "contracts" / "openapi.json"


def main() -> None:
    # Placeholder values: the app is only introspected, never started or connected.
    settings = Settings(
        session_token=secrets.token_urlsafe(32),  # type: ignore[arg-type]
        database_url="postgresql+psycopg://contract-export@127.0.0.1/none",  # type: ignore[arg-type]
    )
    spec = create_app(settings).openapi()
    OUT.write_text(json.dumps(spec, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
