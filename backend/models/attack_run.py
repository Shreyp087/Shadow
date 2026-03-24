from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, Numeric, CheckConstraint, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, UUIDPrimaryKeyMixin
from .enums import AttackRunStatus


class AttackRun(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "attack_runs"
    __table_args__ = (
        CheckConstraint("total_attacks >= 0", name="total_attacks_non_negative"),
        CheckConstraint("vulnerabilities_found >= 0", name="vulnerabilities_found_non_negative"),
    )

    target_system_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("target_systems.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status: Mapped[AttackRunStatus] = mapped_column(
        Enum(AttackRunStatus, name="attack_run_status", native_enum=True),
        nullable=False,
        default=AttackRunStatus.PENDING,
        server_default=text(f"'{AttackRunStatus.PENDING.value}'"),
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    total_attacks: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    vulnerabilities_found: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    risk_score_avg: Mapped[Decimal | None] = mapped_column(Numeric(5, 2), nullable=True)

    target_system: Mapped["TargetSystem"] = relationship(back_populates="attack_runs")
    user: Mapped["User"] = relationship(back_populates="attack_runs")
    attack_results: Mapped[list["AttackResult"]] = relationship(back_populates="attack_run")
