from __future__ import annotations

import asyncio
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select

BACKEND_DIR = Path(__file__).resolve().parents[1]

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from models.base import AsyncSessionLocal
from models.llm_role_setting import LLMRoleSetting
from models.target_system import TargetSystem
from utils.encryption import rotate_value


@dataclass(frozen=True)
class RotationSummary:
    target_credentials: int
    llm_role_credentials: int

    @property
    def total(self) -> int:
        return self.target_credentials + self.llm_role_credentials


async def rotate_stored_credentials() -> RotationSummary:
    if not os.getenv("ENCRYPTION_KEY_PREVIOUS", "").strip():
        raise RuntimeError(
            "ENCRYPTION_KEY_PREVIOUS must contain at least one old key before rotation"
        )

    target_credentials = 0
    llm_role_credentials = 0
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(TargetSystem))
        for target_system in result.scalars().all():
            target_system.api_key_encrypted = rotate_value(
                target_system.api_key_encrypted
            )
            target_credentials += 1

        llm_settings_result = await session.execute(
            select(LLMRoleSetting).where(
                LLMRoleSetting.api_key_encrypted.is_not(None)
            )
        )
        for setting in llm_settings_result.scalars().all():
            if setting.api_key_encrypted is None:
                continue
            setting.api_key_encrypted = rotate_value(setting.api_key_encrypted)
            llm_role_credentials += 1

        await session.commit()

    return RotationSummary(
        target_credentials=target_credentials,
        llm_role_credentials=llm_role_credentials,
    )


async def rotate_target_keys() -> int:
    """Backward-compatible entry point for the existing npm rotation command."""
    return (await rotate_stored_credentials()).total


async def main() -> None:
    summary = await rotate_stored_credentials()
    print(f"Rotated target credentials: {summary.target_credentials}")
    print(f"Rotated LLM role credentials: {summary.llm_role_credentials}")
    print(f"Rotated credentials total: {summary.total}")
    print(
        "Verify target and LLM provider access, then remove "
        "ENCRYPTION_KEY_PREVIOUS from the environment."
    )


if __name__ == "__main__":
    asyncio.run(main())
