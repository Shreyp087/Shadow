from __future__ import annotations

from sqlalchemy import Boolean, Enum, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, UUIDPrimaryKeyMixin
from .enums import AttackVectorCategory, SeverityLevel


class AttackVector(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "attack_vectors"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    category: Mapped[AttackVectorCategory] = mapped_column(
        Enum(AttackVectorCategory, name="attack_vector_category", native_enum=True),
        nullable=False,
        index=True,
    )
    prompt_template: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[SeverityLevel] = mapped_column(
        Enum(SeverityLevel, name="severity_level", native_enum=True),
        nullable=False,
        index=True,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
    )

    attack_results: Mapped[list["AttackResult"]] = relationship(back_populates="attack_vector")

