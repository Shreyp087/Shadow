from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from models.attack_run import AttackRun
from models.target_system import TargetSystem
from models.user import User

DEMO_CLERK_USER_ID = "demo_shadowledger_host"


async def resolve_request_user(db_session: AsyncSession, clerk_user_id: str) -> User:
    statement = select(User).where(User.clerk_user_id == clerk_user_id)
    user = await db_session.scalar(statement)

    if user is not None and not await _should_use_demo_fallback(db_session, user):
        return user

    if _demo_fallback_enabled():
        demo_user = await _get_demo_user(db_session)
        if demo_user is not None:
            return demo_user

    if user is not None:
        return user

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Authenticated user was not found",
    )


async def resolve_mutating_user(db_session: AsyncSession, clerk_user_id: str) -> User:
    statement = select(User).where(User.clerk_user_id == clerk_user_id)
    user = await db_session.scalar(statement)
    if user is not None:
        return user

    user = User(
        clerk_user_id=clerk_user_id,
        email=f"{clerk_user_id}@shadowledger.local",
    )
    db_session.add(user)
    await db_session.flush()
    return user


async def _should_use_demo_fallback(db_session: AsyncSession, user: User) -> bool:
    if not _demo_fallback_enabled() or user.clerk_user_id == DEMO_CLERK_USER_ID:
        return False

    if await _user_has_owned_resources(db_session, user):
        return False

    return await _get_demo_user(db_session) is not None


async def _user_has_owned_resources(db_session: AsyncSession, user: User) -> bool:
    target_system_count = await db_session.scalar(
        select(func.count(TargetSystem.id)).where(TargetSystem.user_id == user.id)
    )
    if int(target_system_count or 0) > 0:
        return True

    attack_run_count = await db_session.scalar(
        select(func.count(AttackRun.id)).where(AttackRun.user_id == user.id)
    )
    return int(attack_run_count or 0) > 0


async def _get_demo_user(db_session: AsyncSession) -> User | None:
    statement = select(User).where(User.clerk_user_id == DEMO_CLERK_USER_ID)
    return await db_session.scalar(statement)


def _demo_fallback_enabled() -> bool:
    return get_settings().environment.lower() != "production"
