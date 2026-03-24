from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import ConfigDict

from .common import ORMResponseModel


class UserResponse(ORMResponseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    clerk_user_id: str
    email: str
    created_at: datetime
