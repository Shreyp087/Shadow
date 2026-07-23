from __future__ import annotations

from time import perf_counter
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db_session
from auth.clerk import verify_clerk_token
from models.enums import LLMProvider, LLMRole
from models.llm_role_setting import LLMRoleSetting
from models.user import User
from routes._user_context import resolve_mutating_user, resolve_request_user
from schemas.common import APIResponse
from schemas.llm_role_setting import (
    LLMConnectionTestResponse,
    LLMRoleSettingResponse,
    OPENAI_API_BASE_URL,
    UpdateLLMRoleSettingRequest,
    canonicalize_llm_base_url,
)
from services.llm_role_settings import (
    LLMSettingsConfigurationError,
    load_stored_llm_role_settings,
    resolve_effective_llm_role_setting,
    resolve_public_llm_role_setting,
)
from utils.encryption import encrypt_value

router = APIRouter(prefix="/api/v1/llm-role-settings", tags=["llm-role-settings"])

DbSession = Annotated[AsyncSession, Depends(get_db_session)]
ClerkUserId = Annotated[str, Depends(verify_clerk_token)]


@router.get("", response_model=APIResponse[list[LLMRoleSettingResponse]])
async def list_llm_role_settings(
    db_session: DbSession,
    clerk_user_id: ClerkUserId,
) -> APIResponse[list[LLMRoleSettingResponse]]:
    user = await _get_authenticated_user(db_session, clerk_user_id)
    stored_by_role = await load_stored_llm_role_settings(db_session, user.id)
    items = [
        _serialize_role_setting(role, stored_by_role.get(role))
        for role in LLMRole
    ]
    return APIResponse(data=items, meta={"count": len(items)})


@router.put("/{role}", response_model=APIResponse[LLMRoleSettingResponse])
async def update_llm_role_setting(
    role: LLMRole,
    payload: UpdateLLMRoleSettingRequest,
    db_session: DbSession,
    clerk_user_id: ClerkUserId,
) -> APIResponse[LLMRoleSettingResponse]:
    user = await _get_mutating_user(db_session, clerk_user_id)
    setting = await db_session.scalar(
        select(LLMRoleSetting).where(
            LLMRoleSetting.user_id == user.id,
            LLMRoleSetting.role == role,
        )
    )

    encrypted_api_key: str | None = None
    if payload.api_key is not None:
        try:
            encrypted_api_key = encrypt_value(payload.api_key.get_secret_value())
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="API credential encryption is unavailable",
            ) from exc

    base_url = (
        OPENAI_API_BASE_URL
        if payload.provider is LLMProvider.HOSTED_OPENAI
        else canonicalize_llm_base_url(payload.base_url)
    )

    if setting is None:
        setting = LLMRoleSetting(
            user_id=user.id,
            role=role,
            provider=payload.provider,
            model_name=payload.model_name,
            base_url=base_url,
            api_key_encrypted=encrypted_api_key,
            api_key_provider=payload.provider if encrypted_api_key else None,
        )
        db_session.add(setting)
    else:
        # Bind a retained secret to the provider it was entered for. This prevents
        # an OpenAI credential from being forwarded when the role switches local.
        if setting.api_key_encrypted and setting.api_key_provider is None:
            setting.api_key_provider = setting.provider
        setting.provider = payload.provider
        setting.model_name = payload.model_name
        setting.base_url = base_url
        if encrypted_api_key is not None:
            setting.api_key_encrypted = encrypted_api_key
            setting.api_key_provider = payload.provider

    if (
        payload.provider is LLMProvider.HOSTED_OPENAI
        and not resolve_public_llm_role_setting(role, setting).api_key_configured
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "A hosted OpenAI API key is required. Enter one for this role "
                "or configure the server-side OPENAI_API_KEY fallback."
            ),
        )

    await db_session.commit()
    await db_session.refresh(setting)

    return APIResponse(
        data=_serialize_role_setting(role, setting),
        meta={"api_key_updated": encrypted_api_key is not None},
    )


@router.post("/{role}/test", response_model=APIResponse[LLMConnectionTestResponse])
async def test_llm_role_setting(
    role: LLMRole,
    db_session: DbSession,
    clerk_user_id: ClerkUserId,
) -> APIResponse[LLMConnectionTestResponse]:
    user = await _get_authenticated_user(db_session, clerk_user_id)
    stored_by_role = await load_stored_llm_role_settings(db_session, user.id)

    try:
        setting = resolve_effective_llm_role_setting(role, stored_by_role.get(role))
    except LLMSettingsConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    started_at = perf_counter()
    ok, message = await _probe_chat_completion(
        provider=setting.provider,
        base_url=setting.base_url,
        api_key=setting.api_key.get_secret_value(),
        model_name=setting.model_name,
    )
    latency_ms = max(0, round((perf_counter() - started_at) * 1000))

    return APIResponse(
        data=LLMConnectionTestResponse(
            role=role,
            ok=ok,
            message=message,
            model_name=setting.model_name,
            base_url=setting.base_url,
            latency_ms=latency_ms,
        )
    )


async def _probe_chat_completion(
    *,
    provider: LLMProvider,
    base_url: str,
    api_key: str,
    model_name: str,
) -> tuple[bool, str]:
    timeout_seconds = (
        180.0
        if provider is LLMProvider.LOCAL_OPENAI_COMPATIBLE
        else 60.0
    )
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = await client.post(
                f"{base_url.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": model_name,
                    "messages": [
                        {
                            "role": "system",
                            "content": "Respond with a short plain-text acknowledgement.",
                        },
                        {"role": "user", "content": "Reply with OK."},
                    ],
                    "max_tokens": 32,
                    "temperature": 0,
                },
            )
            response.raise_for_status()
            payload = response.json()
    except httpx.HTTPStatusError as exc:
        return False, f"Provider returned HTTP {exc.response.status_code}"
    except (httpx.HTTPError, ValueError):
        return False, "Provider connection or response validation failed"

    choices = payload.get("choices") if isinstance(payload, dict) else None
    first_choice = choices[0] if isinstance(choices, list) and choices else None
    message_payload = first_choice.get("message") if isinstance(first_choice, dict) else None
    content = message_payload.get("content") if isinstance(message_payload, dict) else None
    if not isinstance(content, str) or not content.strip():
        return False, "Provider responded, but the configured model returned no chat content"

    return True, "Chat completion succeeded with the configured model"


async def _get_authenticated_user(db_session: AsyncSession, clerk_user_id: str) -> User:
    return await resolve_request_user(db_session, clerk_user_id)


async def _get_mutating_user(db_session: AsyncSession, clerk_user_id: str) -> User:
    return await resolve_mutating_user(db_session, clerk_user_id)


def _serialize_role_setting(
    role: LLMRole,
    setting: LLMRoleSetting | None,
) -> LLMRoleSettingResponse:
    try:
        resolved = resolve_public_llm_role_setting(role, setting)
    except LLMSettingsConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Stored LLM role configuration is invalid",
        ) from exc

    return LLMRoleSettingResponse(
        role=resolved.role,
        provider=resolved.provider,
        model_name=resolved.model_name,
        base_url=resolved.base_url,
        api_key_configured=resolved.api_key_configured,
        is_default=resolved.is_default,
    )
