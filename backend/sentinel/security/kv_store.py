"""Key-value store used for rate limiting, tool call counters and the PII vault.

Redis is the primary backend. When Redis is unreachable and
``SENTINEL_REDIS_OPTIONAL=true`` an in-process store is used instead; this keeps
limits enforced (not disabled) but they are per-process only. The active
backend is reported by ``/api/v1/health``.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Protocol

logger = logging.getLogger(__name__)


class KVStore(Protocol):
    backend: str

    async def incr_window(self, key: str, window_seconds: int) -> int: ...
    async def get(self, key: str) -> bytes | None: ...
    async def set(self, key: str, value: bytes, ttl_seconds: int) -> None: ...
    async def delete(self, key: str) -> None: ...
    async def ping(self) -> bool: ...
    async def close(self) -> None: ...


class MemoryStore:
    """Process-local fallback store with TTL semantics."""

    backend = "memory"

    def __init__(self) -> None:
        self._data: dict[str, tuple[bytes, float]] = {}
        self._lock = asyncio.Lock()

    def _expired(self, key: str, now: float) -> bool:
        item = self._data.get(key)
        return item is None or item[1] <= now

    async def incr_window(self, key: str, window_seconds: int) -> int:
        async with self._lock:
            now = time.monotonic()
            if self._expired(key, now):
                self._data[key] = (b"1", now + window_seconds)
                return 1
            value, exp = self._data[key]
            new = int(value) + 1
            self._data[key] = (str(new).encode(), exp)
            return new

    async def get(self, key: str) -> bytes | None:
        async with self._lock:
            now = time.monotonic()
            if self._expired(key, now):
                self._data.pop(key, None)
                return None
            return self._data[key][0]

    async def set(self, key: str, value: bytes, ttl_seconds: int) -> None:
        async with self._lock:
            self._data[key] = (value, time.monotonic() + ttl_seconds)
            if len(self._data) > 50_000:  # bound memory: drop expired entries
                now = time.monotonic()
                for k in [k for k, (_, e) in self._data.items() if e <= now]:
                    self._data.pop(k, None)

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._data.pop(key, None)

    async def ping(self) -> bool:
        return True

    async def close(self) -> None:
        return None


class RedisStore:
    backend = "redis"

    def __init__(self, url: str) -> None:
        from redis import asyncio as aioredis

        self._redis = aioredis.from_url(url, socket_connect_timeout=2, socket_timeout=2)

    async def incr_window(self, key: str, window_seconds: int) -> int:
        pipe = self._redis.pipeline()
        pipe.incr(key)
        pipe.expire(key, window_seconds, nx=True)
        result = await pipe.execute()
        return int(result[0])

    async def get(self, key: str) -> bytes | None:
        value = await self._redis.get(key)
        if value is None or isinstance(value, bytes):
            return value
        return str(value).encode()

    async def set(self, key: str, value: bytes, ttl_seconds: int) -> None:
        await self._redis.set(key, value, ex=ttl_seconds)

    async def delete(self, key: str) -> None:
        await self._redis.delete(key)

    async def ping(self) -> bool:
        try:
            return bool(await self._redis.ping())
        except Exception:
            return False

    async def close(self) -> None:
        await self._redis.aclose()


async def build_store(redis_url: str, optional: bool) -> KVStore:
    try:
        store = RedisStore(redis_url)
        if await store.ping():
            logger.info("Connected to Redis")
            return store
        await store.close()
        raise ConnectionError("Redis ping failed")
    except Exception as exc:
        if not optional:
            raise RuntimeError("Redis is required but unreachable") from exc
        logger.warning("Redis unavailable (%s); using in-process store (single instance only)", type(exc).__name__)
        return MemoryStore()
