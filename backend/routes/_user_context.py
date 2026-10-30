from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError

from auth.clerk import DEMO_CLERK_USER_ID, demo_auth_enabled
from models.user import User


async def resolve_request_user(db_session: AsyncSession, clerk_user_id: str) -> User:
    _reject_disabled_demo_identity(clerk_user_id)
    return await _get_or_create_user(db_session, clerk_user_id)


async def resolve_mutating_user(db_session: AsyncSession, clerk_user_id: str) -> User:
    _reject_disabled_demo_identity(clerk_user_id)
    return await _get_or_create_user(db_session, clerk_user_id)


async def _get_or_create_user(db_session: AsyncSession, clerk_user_id: str) -> User:
    statement = select(User).where(User.clerk_user_id == clerk_user_id)
    user = await db_session.scalar(statement)
    if user is not None:
        return user

    user = User(
        clerk_user_id=clerk_user_id,
        email=f"{clerk_user_id}@shadowledger.local",
    )
    try:
        async with db_session.begin_nested():
            db_session.add(user)
            await db_session.flush()
        # A first authenticated GET must persist its identity for parallel
        # dashboard requests and per-user starter provisioning.
        await db_session.commit()
    except IntegrityError:
        user = await db_session.scalar(statement)
        if user is None:
            raise
    return user


def _reject_disabled_demo_identity(clerk_user_id: str) -> None:
    if clerk_user_id == DEMO_CLERK_USER_ID and not demo_auth_enabled():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Demo authentication is not enabled",
        )
