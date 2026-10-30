from __future__ import annotations

import os
from dataclasses import dataclass
from uuid import UUID

from pydantic import SecretStr, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.enums import LLMProvider, LLMRole
from models.llm_role_setting import LLMRoleSetting
from schemas.llm_role_setting import (
    OPENAI_API_BASE_URL,
    HOSTED_API_BASE_URLS,
    UpdateLLMRoleSettingRequest,
    canonicalize_llm_base_url,
)
from utils.encryption import decrypt_value

LOCAL_AUTH_PLACEHOLDER = "lm-studio"
HOSTED_KEY_ENV = {
    LLMProvider.HOSTED_OPENAI: "OPENAI_API_KEY",
    LLMProvider.HOSTED_ANTHROPIC: "ANTHROPIC_API_KEY",
}

_DEFAULT_MODEL_ENV = {
    LLMRole.ATTACKER: "OPENAI_ATTACKER_MODEL",
    LLMRole.MUTATOR: "OPENAI_MUTATION_MODEL",
    LLMRole.JUDGE: "OPENAI_SCORER_MODEL",
}


class LLMSettingsConfigurationError(RuntimeError):
    """Raised when an effective role configuration cannot be used safely."""


@dataclass(frozen=True)
class EffectiveLLMRoleSetting:
    role: LLMRole
    provider: LLMProvider
    model_name: str
    base_url: str
    api_key: SecretStr
    is_default: bool


@dataclass(frozen=True)
class PublicLLMRoleSetting:
    role: LLMRole
    provider: LLMProvider
    model_name: str
    base_url: str
    api_key_configured: bool
    is_default: bool


async def load_effective_llm_role_settings(
    db_session: AsyncSession,
    user_id: UUID,
) -> dict[LLMRole, EffectiveLLMRoleSetting]:
    """Load all role settings, applying legacy environment defaults for missing rows."""
    stored_by_role = await load_stored_llm_role_settings(db_session, user_id)
    effective: dict[LLMRole, EffectiveLLMRoleSetting] = {}

    for role in LLMRole:
        effective[role] = resolve_effective_llm_role_setting(
            role,
            stored_by_role.get(role),
        )

    return effective


async def load_stored_llm_role_settings(
    db_session: AsyncSession,
    user_id: UUID,
) -> dict[LLMRole, LLMRoleSetting]:
    result = await db_session.execute(
        select(LLMRoleSetting).where(LLMRoleSetting.user_id == user_id)
    )
    return {setting.role: setting for setting in result.scalars().all()}


def resolve_effective_llm_role_setting(
    role: LLMRole,
    setting: LLMRoleSetting | None,
) -> EffectiveLLMRoleSetting:
    public_setting = resolve_public_llm_role_setting(role, setting)
    api_key = _resolve_api_key(role, setting, public_setting.provider)
    return EffectiveLLMRoleSetting(
        role=role,
        provider=public_setting.provider,
        model_name=public_setting.model_name,
        base_url=public_setting.base_url,
        api_key=SecretStr(api_key),
        is_default=public_setting.is_default,
    )


def resolve_public_llm_role_setting(
    role: LLMRole,
    setting: LLMRoleSetting | None,
) -> PublicLLMRoleSetting:
    if setting is None:
        return PublicLLMRoleSetting(
            role=role,
            provider=LLMProvider.HOSTED_OPENAI,
            model_name=_default_model(role),
            base_url=OPENAI_API_BASE_URL,
            api_key_configured=bool(os.getenv("OPENAI_API_KEY", "").strip()),
            is_default=True,
        )

    base_url = _validated_base_url(setting)
    return PublicLLMRoleSetting(
        role=role,
        provider=setting.provider,
        model_name=setting.model_name,
        base_url=base_url,
        api_key_configured=_has_effective_configured_key(setting),
        is_default=False,
    )


def _default_model(role: LLMRole) -> str:
    return os.getenv(_DEFAULT_MODEL_ENV[role], "gpt-4o-mini").strip() or "gpt-4o-mini"


def _validated_base_url(setting: LLMRoleSetting) -> str:
    raw_base_url = HOSTED_API_BASE_URLS.get(setting.provider, setting.base_url)
    if not raw_base_url:
        raise LLMSettingsConfigurationError(
            f"The {setting.role.value} role is missing its local provider base URL"
        )

    try:
        validated = UpdateLLMRoleSettingRequest(
            provider=setting.provider,
            model_name=setting.model_name,
            base_url=raw_base_url,
        )
    except ValidationError as exc:
        raise LLMSettingsConfigurationError(
            f"The stored {setting.role.value} role configuration is invalid"
        ) from exc

    return HOSTED_API_BASE_URLS.get(setting.provider) or canonicalize_llm_base_url(validated.base_url)


def _has_effective_configured_key(setting: LLMRoleSetting) -> bool:
    credential_provider = setting.api_key_provider or setting.provider
    has_matching_stored_key = bool(setting.api_key_encrypted) and credential_provider is setting.provider
    if has_matching_stored_key:
        return True
    if setting.provider in HOSTED_KEY_ENV:
        return bool(os.getenv(HOSTED_KEY_ENV[setting.provider], "").strip())
    return False


def _resolve_api_key(
    role: LLMRole,
    setting: LLMRoleSetting | None,
    provider: LLMProvider,
) -> str:
    if setting is not None:
        credential_provider = setting.api_key_provider or setting.provider
        if setting.api_key_encrypted and credential_provider is provider:
            try:
                return decrypt_value(setting.api_key_encrypted)
            except ValueError as exc:
                raise LLMSettingsConfigurationError(
                    f"The stored API credential for the {role.value} role cannot be decrypted"
                ) from exc

    if provider is LLMProvider.LOCAL_OPENAI_COMPATIBLE:
        return LOCAL_AUTH_PLACEHOLDER

    environment_key = os.getenv(HOSTED_KEY_ENV[provider], "").strip()
    if environment_key:
        return environment_key

    raise LLMSettingsConfigurationError(
        f"No API key is configured for the {role.value} hosted "
        f"{'Anthropic' if provider is LLMProvider.HOSTED_ANTHROPIC else 'OpenAI'} role"
    )
