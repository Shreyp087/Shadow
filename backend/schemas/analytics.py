from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import BaseModel, Field

from models.enums import AttackVectorCategory, RiskCategory

AttackSurfaceTrend = Literal["IMPROVING", "WORSENING", "STABLE"]


class TargetRiskTrendPoint(BaseModel):
    date: date
    avg_risk_score: float = Field(ge=0, le=100)
    total_attacks: int = Field(ge=0)
    critical_count: int = Field(ge=0)
    high_count: int = Field(ge=0)
    medium_count: int = Field(ge=0)


class AttackSurfaceSummaryItem(BaseModel):
    category: AttackVectorCategory
    worst_risk: RiskCategory
    total_attacks: int = Field(ge=0)
    high_critical_count: int = Field(ge=0)
    trend: AttackSurfaceTrend
