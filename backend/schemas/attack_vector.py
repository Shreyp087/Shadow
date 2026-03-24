from __future__ import annotations

from uuid import UUID

from pydantic import ConfigDict

from models.enums import AttackVectorCategory, SeverityLevel

from .common import ORMResponseModel


class AttackVectorResponse(ORMResponseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    category: AttackVectorCategory
    prompt_template: str
    severity: SeverityLevel
    is_active: bool
