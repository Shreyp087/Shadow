from __future__ import annotations

import asyncio
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from models.base import AsyncSessionLocal
from seeds.attack_vectors import seed_attack_vectors


async def main() -> None:
    async with AsyncSessionLocal() as session:
        summary = await seed_attack_vectors(session)

    print("Attack vector seed completed.")
    print(f"Expected vectors: {summary['expected']}")
    print(f"Created vectors: {summary['created']}")
    print(f"Updated vectors: {summary['updated']}")
    print(f"Total vectors after seed: {summary['total_after_seed']}")


if __name__ == "__main__":
    asyncio.run(main())
