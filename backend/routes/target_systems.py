from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db_session
from auth.clerk import verify_clerk_token
from models.target_system import TargetSystem
from models.user import User
from routes._user_context import resolve_mutating_user, resolve_request_user
from schemas.common import APIResponse
from schemas.target_system import CreateTargetSystemRequest, TargetSystemResponse
from utils.encryption import encrypt_value
from services.starter_targets import ensure_starter_targets, starter_spec, target_credential_source

router = APIRouter(prefix="/api/v1/target-systems", tags=["target-systems"])

DbSession = Annotated[AsyncSession, Depends(get_db_session)]
ClerkUserId = Annotated[str, Depends(verify_clerk_token)]


@router.get("", response_model=APIResponse[list[TargetSystemResponse]])
async def list_target_systems(
    db_session: DbSession,
    clerk_user_id: ClerkUserId,
) -> APIResponse[list[TargetSystemResponse]]:
    user = await _get_authenticated_user(db_session, clerk_user_id)
    await ensure_starter_targets(db_session, user.id)
    statement = (
        select(TargetSystem)
        .where(TargetSystem.user_id == user.id)
        .order_by(TargetSystem.created_at.desc(), TargetSystem.name.asc())
    )
    result = await db_session.execute(statement)
    items = [_serialize_target_system(system) for system in result.scalars().all()]

    return APIResponse(
        data=items,
        meta={"count": len(items)},
    )


@router.post("", response_model=APIResponse[TargetSystemResponse], status_code=status.HTTP_201_CREATED)
async def create_target_system(
    payload: CreateTargetSystemRequest,
    db_session: DbSession,
    clerk_user_id: ClerkUserId,
) -> APIResponse[TargetSystemResponse]:
    user = await _get_mutating_user(db_session, clerk_user_id)

    try:
        encrypted_api_key = encrypt_value(payload.api_key.get_secret_value())
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc

    target_system = TargetSystem(
        user_id=user.id,
        name=payload.name,
        description=payload.description,
        api_endpoint=str(payload.api_endpoint),
        target_type=payload.target_type,
        api_key_encrypted=encrypted_api_key,
        model_name=payload.model_name,
        is_active=payload.is_active,
    )
    db_session.add(target_system)
    await db_session.commit()
    await db_session.refresh(target_system)

    return APIResponse(
        data=_serialize_target_system(target_system),
        meta={"api_key_configured": True},
    )


async def _get_authenticated_user(db_session: AsyncSession, clerk_user_id: str) -> User:
    return await resolve_request_user(db_session, clerk_user_id)


async def _get_mutating_user(db_session: AsyncSession, clerk_user_id: str) -> User:
    return await resolve_mutating_user(db_session, clerk_user_id)


def _serialize_target_system(target_system: TargetSystem) -> TargetSystemResponse:
    return TargetSystemResponse(
        id=target_system.id,
        user_id=target_system.user_id,
        name=target_system.name,
        description=target_system.description,
        api_endpoint=target_system.api_endpoint,
        target_type=target_system.target_type,
        api_key_configured=target_credential_source(target_system) != "none",
        credential_source=target_credential_source(target_system),
        is_starter=starter_spec(target_system) is not None,
        model_name=target_system.model_name,
        created_at=target_system.created_at,
        is_active=target_system.is_active,
    )
