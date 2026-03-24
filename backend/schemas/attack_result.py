from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import ConfigDict, Field

from models.enums import AttackVectorCategory, RiskCategory

from .common import ORMResponseModel


class AttackResultResponse(ORMResponseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    attack_run_id: UUID
    attack_vector_id: UUID
    attack_category: AttackVectorCategory | None = None
    prompt_sent: str
    response_received: str
    risk_score: int = Field(ge=0, le=100)
    is_mutation: bool
    risk_category: RiskCategory
    risk_reason: str
    executed_at: datetime
    trust_ledger_entry_hash: str | None = None
