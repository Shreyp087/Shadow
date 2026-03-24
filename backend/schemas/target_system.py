from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from models.enums import TargetSystemType

from .common import ORMResponseModel


class CreateTargetSystemRequest(BaseModel):
    name: str
    description: str | None = None
    api_endpoint: str
    target_type: TargetSystemType
    api_key: str = Field(min_length=1)
    model_name: str
    is_active: bool = True


class TargetSystemResponse(ORMResponseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    user_id: UUID
    name: str
    description: str | None
    api_endpoint: str
    target_type: TargetSystemType
    api_key_masked: str
    model_name: str
    created_at: datetime
    is_active: bool
