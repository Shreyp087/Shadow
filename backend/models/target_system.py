from __future__ import annotations

import uuid

from sqlalchemy import Boolean, Enum, ForeignKey, String, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin
from .enums import TargetSystemType


def _enum_values(enum_cls: type[TargetSystemType]) -> list[str]:
    return [member.value for member in enum_cls]


class TargetSystem(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "target_systems"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    api_endpoint: Mapped[str] = mapped_column(String(2048), nullable=False)
    target_type: Mapped[TargetSystemType] = mapped_column(
        Enum(
            TargetSystemType,
            name="target_system_type",
            native_enum=True,
            values_callable=_enum_values,
        ),
        nullable=False,
        default=TargetSystemType.OPENAI_COMPATIBLE,
        server_default=text(f"'{TargetSystemType.OPENAI_COMPATIBLE.value}'"),
    )
    api_key_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    model_name: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
    )

    user: Mapped["User"] = relationship(back_populates="target_systems")
    attack_runs: Mapped[list["AttackRun"]] = relationship(back_populates="target_system")
