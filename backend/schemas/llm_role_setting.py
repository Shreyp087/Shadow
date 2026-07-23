from __future__ import annotations

from typing import Any

from pydantic import AnyHttpUrl, BaseModel, Field, SecretStr, ValidationInfo, field_validator

from app.core.config import get_settings
from models.enums import LLMProvider, LLMRole
from utils.network_security import parse_ip_literal

OPENAI_API_BASE_URL = "https://api.openai.com/v1"


class UpdateLLMRoleSettingRequest(BaseModel):
    provider: LLMProvider
    model_name: str = Field(min_length=1, max_length=255)
    base_url: AnyHttpUrl | None = Field(default=None, max_length=2048, validate_default=True)
    api_key: SecretStr | None = None

    @field_validator("model_name")
    @classmethod
    def normalize_model_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Model name must not be blank")
        return normalized

    @field_validator("api_key", mode="before")
    @classmethod
    def normalize_optional_api_key(cls, value: Any) -> Any:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("base_url")
    @classmethod
    def validate_provider_endpoint(
        cls,
        base_url: AnyHttpUrl | None,
        info: ValidationInfo,
    ) -> AnyHttpUrl | None:
        provider = info.data.get("provider")
        if not isinstance(provider, LLMProvider):
            return base_url
        if provider is LLMProvider.HOSTED_OPENAI:
            if base_url is not None and canonicalize_llm_base_url(base_url) != OPENAI_API_BASE_URL:
                raise ValueError(
                    f"Hosted OpenAI uses the fixed base URL {OPENAI_API_BASE_URL}"
                )
            return base_url

        settings = get_settings()
        if settings.environment.lower() != "development":
            raise ValueError("Local OpenAI-compatible providers are development-only")
        if base_url is None:
            raise ValueError("A base URL is required for a local OpenAI-compatible provider")
        _require_safe_loopback_url(base_url)
        return base_url


class LLMRoleSettingResponse(BaseModel):
    role: LLMRole
    provider: LLMProvider
    model_name: str
    base_url: str
    api_key_configured: bool
    is_default: bool


class LLMConnectionTestResponse(BaseModel):
    role: LLMRole
    ok: bool
    message: str
    model_name: str
    base_url: str
    latency_ms: int


def canonicalize_llm_base_url(url: AnyHttpUrl | str) -> str:
    normalized = str(url).rstrip("/")
    completion_suffix = "/chat/completions"
    if normalized.endswith(completion_suffix):
        normalized = normalized[: -len(completion_suffix)].rstrip("/")
    return normalized


def _require_safe_loopback_url(url: AnyHttpUrl) -> None:
    if url.username is not None or url.password is not None:
        raise ValueError("Local provider base URL must not include credentials")
    if url.query is not None or url.fragment is not None:
        raise ValueError("Local provider base URL must not include query parameters or fragments")
    if url.scheme not in {"http", "https"}:
        raise ValueError("Local provider base URL must use HTTP or HTTPS")

    hostname = (url.host or "").strip().lower().removesuffix(".")
    literal_address = parse_ip_literal(hostname)
    is_loopback = hostname == "localhost" or (
        literal_address is not None and literal_address.is_loopback
    )
    if not is_loopback:
        raise ValueError(
            "Local provider base URL must use localhost, 127.0.0.0/8, or ::1"
        )
