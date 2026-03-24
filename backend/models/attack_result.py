from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, Enum, ForeignKey, Integer, Text, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, UUIDPrimaryKeyMixin
from .enums import RiskCategory


class AttackResult(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "attack_results"
    __table_args__ = (
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="risk_score_range"),
    )

    attack_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("attack_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    attack_vector_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("attack_vectors.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    prompt_sent: Mapped[str] = mapped_column(Text, nullable=False)
    response_received: Mapped[str] = mapped_column(Text, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    is_mutation: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    risk_category: Mapped[RiskCategory] = mapped_column(
        Enum(RiskCategory, name="risk_category", native_enum=True),
        nullable=False,
        index=True,
    )
    risk_reason: Mapped[str] = mapped_column(Text, nullable=False)
    executed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    attack_run: Mapped["AttackRun"] = relationship(back_populates="attack_results")
    attack_vector: Mapped["AttackVector"] = relationship(back_populates="attack_results")
    trust_ledger_entries: Mapped[list["TrustLedgerEntry"]] = relationship(back_populates="attack_result")
