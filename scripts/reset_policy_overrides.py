"""Deactivate runtime policy overrides stored in the database.

Policy sections changed through PUT /api/v1/policies/{id} are persisted and take
precedence over backend/policies/default.yaml on restart. Run this (with the
gateway stopped) to return to the YAML file policy. History rows are kept.

Usage: backend/.venv/Scripts/python scripts/reset_policy_overrides.py [--section prompt_injection]
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from sqlalchemy import update  # noqa: E402

from sentinel.config import get_settings  # noqa: E402
from sentinel.db.models import AuditLog, PolicyRecord  # noqa: E402
from sentinel.db.session import build_database  # noqa: E402


async def main(section: str | None) -> None:
    db = build_database(get_settings())
    await db.create_all()
    async with db.sessionmaker() as s:
        stmt = update(PolicyRecord).where(PolicyRecord.is_active.is_(True))
        if section:
            stmt = stmt.where(PolicyRecord.policy_id == section)
        res = await s.execute(stmt.values(is_active=False))
        s.add(AuditLog(actor="cli", action="policy.reset_overrides", target=section or "*", details={"rows": res.rowcount}))
        await s.commit()
        print(f"Deactivated {res.rowcount} override record(s)")
    await db.dispose()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--section", default=None)
    asyncio.run(main(ap.parse_args().section))
