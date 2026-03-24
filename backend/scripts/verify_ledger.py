from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from uuid import UUID

BACKEND_DIR = Path(__file__).resolve().parents[1]

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from models.base import AsyncSessionLocal
from services.trust_ledger import TrustLedger


async def main(attack_run_id: UUID) -> int:
    async with AsyncSessionLocal() as session:
        ledger = TrustLedger(session)
        entries = await ledger.get_entries(attack_run_id)

        if not entries:
            print("BROKEN")
            print(f"No trust ledger entries found for attack run {attack_run_id}")
            return 1

        verification = await ledger.verify_chain(entries[0].id, entries[-1].id)

    if verification.is_valid:
        print("VALID")
        print(f"Verified {len(entries)} entries for attack run {attack_run_id}")
        return 0

    print("BROKEN")
    print(f"First broken entry: {verification.first_broken_entry_id}")
    return 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scripts/verify_ledger.py [attack_run_id]")
        raise SystemExit(1)

    raise SystemExit(asyncio.run(main(UUID(sys.argv[1]))))
