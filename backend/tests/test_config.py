from __future__ import annotations

import pytest
from pydantic import ValidationError

from jarvis.core.config import Settings, load_settings
from jarvis.secrets.store import MemoryStore

TOKEN = "t" * 43


def test_database_url_falls_back_to_os_credential_store(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("JARVIS_DATABASE_URL", raising=False)
    monkeypatch.setenv("JARVIS_SESSION_TOKEN", TOKEN)
    store = MemoryStore()
    store.set("database_url", "postgresql+psycopg://jarvis:s3cret@127.0.0.1/jarvis")
    s = load_settings(store)
    assert s.database_url.get_secret_value().endswith("@127.0.0.1/jarvis")
    assert "s3cret" not in repr(s) and "s3cret" not in str(s.model_dump())


def test_environment_wins_over_store(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JARVIS_DATABASE_URL", "postgresql+psycopg://env@127.0.0.1/x")
    monkeypatch.setenv("JARVIS_SESSION_TOKEN", TOKEN)
    store = MemoryStore()
    store.set("database_url", "postgresql+psycopg://store@127.0.0.1/x")
    assert "env@" in load_settings(store).database_url.get_secret_value()


def test_missing_secrets_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("JARVIS_DATABASE_URL", raising=False)
    monkeypatch.setenv("JARVIS_SESSION_TOKEN", TOKEN)
    with pytest.raises(ValidationError):
        load_settings(MemoryStore())


def test_short_session_token_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(session_token="short", database_url="postgresql://x")  # type: ignore[arg-type]


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "::"])
def test_backend_refuses_non_loopback_bind(host: str) -> None:
    with pytest.raises(ValidationError):
        Settings(session_token=TOKEN, database_url="postgresql://x", host=host)  # type: ignore[arg-type]


def test_workspaces_parse_from_csv(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JARVIS_WORKSPACES", "/a/one, /b/two")
    s = Settings(session_token=TOKEN, database_url="postgresql://x")  # type: ignore[arg-type]
    assert [p.name for p in s.workspaces] == ["one", "two"]
