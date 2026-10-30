from __future__ import annotations

from datetime import datetime
from uuid import UUID
from typing import Literal

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, SecretStr, field_validator

from app.core.config import get_settings
from models.enums import TargetSystemType
from utils.network_security import parse_ip_literal, require_global_ip_address

from .common import ORMResponseModel


class CreateTargetSystemRequest(BaseModel):
    name: str
    description: str | None = None
    api_endpoint: AnyHttpUrl = Field(max_length=2048)
    target_type: TargetSystemType
    api_key: SecretStr = Field(min_length=1)
    model_name: str
    is_active: bool = True

    @field_validator("api_endpoint")
    @classmethod
    def validate_api_endpoint(cls, endpoint: AnyHttpUrl) -> AnyHttpUrl:
        if endpoint.username is not None or endpoint.password is not None:
            raise ValueError("API endpoint must not include credentials")
        if endpoint.fragment is not None:
            raise ValueError("API endpoint must not include a URL fragment")
        if endpoint.query is not None:
            raise ValueError("API endpoint must not include query parameters")

        settings = get_settings()
        if endpoint.scheme != "https":
            insecure_development_endpoint_allowed = (
                settings.environment.lower() == "development"
                and settings.allow_insecure_target_endpoints
            )
            if not insecure_development_endpoint_allowed:
                raise ValueError(
                    "API endpoint must use HTTPS; local HTTP endpoints require "
                    "ALLOW_INSECURE_TARGET_ENDPOINTS=true in development"
                )

        literal_address = parse_ip_literal(endpoint.host)
        if literal_address is not None and not settings.allow_private_target_endpoints:
            require_global_ip_address(literal_address)

        return endpoint


class TargetSystemResponse(ORMResponseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    user_id: UUID
    name: str
    description: str | None
    api_endpoint: str
    target_type: TargetSystemType
    api_key_configured: bool
    credential_source: Literal["personal", "app", "none"] = "personal"
    is_starter: bool = False
    model_name: str
    created_at: datetime
    is_active: bool
