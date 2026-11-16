from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from sqlalchemy import func, select

BACKEND_DIR = Path(__file__).resolve().parents[1]

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from models.attack_result import AttackResult
from models.attack_run import AttackRun
from models.base import AsyncSessionLocal
from models.enums import RiskCategory
from models.target_system import TargetSystem
from models.trust_ledger_entry import TrustLedgerEntry
from models.user import User


async def main() -> int:
    try:
        async with AsyncSessionLocal() as session:
            users_count = int((await session.scalar(select(func.count(User.id)))) or 0)
            target_systems = (
                await session.execute(select(TargetSystem).order_by(TargetSystem.name.asc()))
            ).scalars().all()
            attack_runs = (
                await session.execute(
                    select(AttackRun).order_by(AttackRun.started_at.desc().nullslast(), AttackRun.id.desc())
                )
            ).scalars().all()
            attack_results_count = int((await session.scalar(select(func.count(AttackResult.id)))) or 0)
            risk_breakdown_rows = (
                await session.execute(
                    select(AttackResult.risk_category, func.count(AttackResult.id))
                    .group_by(AttackResult.risk_category)
                    .order_by(AttackResult.risk_category.asc())
                )
            ).all()
            trust_ledger_count = int((await session.scalar(select(func.count(TrustLedgerEntry.id)))) or 0)
    except Exception as exc:
        print("ShadowLedger Demo Data Check")
        print("===========================")
        print(f"Database connection failed: {exc}")
        print("DEMO DATA MISSING - run python -m seeds.demo_data")
        return 1

    print("ShadowLedger Demo Data Check")
    print("===========================")
    print(f"users: {users_count}")
    print(f"target_systems: {len(target_systems)}")
    active_presentation_targets = [
        system
        for system in target_systems
        if system.is_active and ".shadowledger.demo" in system.api_endpoint
    ]
    if target_systems:
        print("target_system names:")
        for system in target_systems:
            print(f"  - {system.name} | active={system.is_active}")

    print(f"attack_runs: {len(attack_runs)}")
    if attack_runs:
        print("attack_runs detail:")
        for run in attack_runs:
            print(
                f"  - {run.id} | status={run.status.value} | risk_score_avg={run.risk_score_avg}"
            )

    print(f"attack_results: {attack_results_count}")
    print("attack_results by risk_category:")
    risk_breakdown = {category.value: 0 for category in RiskCategory}
    for category, count in risk_breakdown_rows:
        risk_breakdown[category.value] = int(count)
    for category_name, count in risk_breakdown.items():
        print(f"  - {category_name}: {count}")

    print(f"trust_ledger_entries: {trust_ledger_count}")

    if active_presentation_targets:
        print("ACTIVE PRESENTATION TARGETS FOUND - rerun python -m seeds.demo_data")
        return 1

    if len(attack_runs) >= 3 and attack_results_count >= 75:
        print("DEMO DATA OK")
        return 0
    else:
        print("DEMO DATA MISSING - run python -m seeds.demo_data")
        return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
