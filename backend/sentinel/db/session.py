"""Async database engine and session management."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from sentinel.config import BACKEND_DIR, Settings
from sentinel.db.models import Base


class Database:
    """Owns the async engine and session factory for the application lifetime."""

    def __init__(self, url: str) -> None:
        self.url = self._prepare_url(url)
        kwargs: dict = {"pool_pre_ping": True}
        if self.url.startswith("sqlite"):
            kwargs = {}
        self.engine: AsyncEngine = create_async_engine(self.url, **kwargs)
        self.sessionmaker = async_sessionmaker(self.engine, expire_on_commit=False)

    @staticmethod
    def _prepare_url(url: str) -> str:
        # Make relative SQLite paths relative to the backend dir and ensure the folder exists.
        prefix = "sqlite+aiosqlite:///"
        if url.startswith(prefix) and not url.startswith(prefix + "/") and ":memory:" not in url:
            rel = url[len(prefix):]
            path = Path(rel)
            if not path.is_absolute():
                path = (BACKEND_DIR / rel).resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            return prefix + path.as_posix()
        return url

    async def create_all(self) -> None:
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def session(self) -> AsyncIterator[AsyncSession]:
        async with self.sessionmaker() as s:
            yield s

    async def ping(self) -> bool:
        from sqlalchemy import text

        try:
            async with self.engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            return True
        except Exception:
            return False

    async def dispose(self) -> None:
        await self.engine.dispose()


def build_database(settings: Settings) -> Database:
    return Database(settings.database_url)
