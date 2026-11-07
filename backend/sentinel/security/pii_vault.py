"""Session-scoped, encrypted placeholder vault.

Used only when ``pii.allow_restoration`` is enabled in policy *and* the
caller explicitly requests restoration. Mappings are Fernet-encrypted with a
key derived from ``SENTINEL_SECRET_KEY`` and expire after the configured TTL.
Restored values are only ever returned to the original caller - never sent to
a provider.
"""

from __future__ import annotations

import base64
import hashlib
import json

from cryptography.fernet import Fernet, InvalidToken

from sentinel.security.kv_store import KVStore


class PIIVault:
    def __init__(self, store: KVStore, secret: bytes) -> None:
        key = base64.urlsafe_b64encode(hashlib.sha256(b"sentinel-pii-vault:" + secret).digest())
        self._fernet = Fernet(key)
        self._store = store

    @staticmethod
    def _key(session_id: str) -> str:
        return "vault:" + hashlib.sha256(session_id.encode()).hexdigest()[:32]

    async def load(self, session_id: str) -> dict[str, str]:
        """Return value->placeholder mapping (internal 'category:value' keys) for the session."""
        blob = await self._store.get(self._key(session_id))
        if not blob:
            return {}
        try:
            return json.loads(self._fernet.decrypt(blob))
        except (InvalidToken, ValueError):
            return {}

    async def save(self, session_id: str, value_to_placeholder: dict[str, str], ttl_seconds: int) -> None:
        pii_only = {k: v for k, v in value_to_placeholder.items() if k.startswith("pii:")}  # never store secrets
        if not pii_only:
            return
        token = self._fernet.encrypt(json.dumps(pii_only).encode())
        await self._store.set(self._key(session_id), token, ttl_seconds)

    async def clear(self, session_id: str) -> None:
        await self._store.delete(self._key(session_id))
