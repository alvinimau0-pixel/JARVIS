"""Secret storage backed by the operating system's credential store.

Windows: Credential Manager. macOS: Keychain. Linux: Secret Service. (via ``keyring``)
Secrets never go into source, config files, the database, logs or the frontend.
"""

from __future__ import annotations

from typing import Protocol

SERVICE = "jarvis-os"
KNOWN_SECRETS = ("database_url", "audit_hmac_key")


class SecretStore(Protocol):
    def get(self, name: str) -> str | None: ...
    def set(self, name: str, value: str) -> None: ...
    def delete(self, name: str) -> None: ...


class KeyringStore:
    def get(self, name: str) -> str | None:
        import keyring
        from keyring.errors import KeyringError

        try:
            return keyring.get_password(SERVICE, name)
        except KeyringError:
            return None

    def set(self, name: str, value: str) -> None:
        import keyring

        keyring.set_password(SERVICE, name, value)

    def delete(self, name: str) -> None:
        import keyring

        keyring.delete_password(SERVICE, name)


class MemoryStore:
    """For tests only."""

    def __init__(self) -> None:
        self._data: dict[str, str] = {}

    def get(self, name: str) -> str | None:
        return self._data.get(name)

    def set(self, name: str, value: str) -> None:
        self._data[name] = value

    def delete(self, name: str) -> None:
        self._data.pop(name, None)
