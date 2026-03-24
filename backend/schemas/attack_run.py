from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from models.enums import AttackRunStatus

from .common import ORMResponseModel


class CreateAttackRunRequest(BaseModel):
    target_system_id: UUID
    vector_category_filter: list[str] | None = None


class AttackRunResponse(ORMResponseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    target_system_id: UUID
    user_id: UUID
    status: AttackRunStatus
    started_at: datetime | None
    completed_at: datetime | None
    total_attacks: int = Field(ge=0)
    vulnerabilities_found: int = Field(ge=0)
    risk_score_avg: Decimal | None


class AttackRunsSummaryResponse(BaseModel):
    total_scans: int = Field(ge=0)
    vulnerabilities_found: int = Field(ge=0)
    critical_findings: int = Field(ge=0)
    avg_risk_score: Decimal | None
