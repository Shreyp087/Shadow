from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

__all__ = ["seed_attack_vectors", "seed_demo_data"]


async def seed_attack_vectors(session: AsyncSession):
    from .attack_vectors import seed_attack_vectors as _seed_attack_vectors

    return await _seed_attack_vectors(session)


async def seed_demo_data(session: AsyncSession):
    from .demo_data import seed_demo_data as _seed_demo_data

    return await _seed_demo_data(session)
