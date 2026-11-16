from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin
from .enums import LLMProvider, LLMRole


def _enum_values(enum_cls: type[LLMRole] | type[LLMProvider]) -> list[str]:
    return [member.value for member in enum_cls]


class LLMRoleSetting(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "llm_role_settings"
    __table_args__ = (
        UniqueConstraint("user_id", "role", name="uq_llm_role_settings_user_id_role"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role: Mapped[LLMRole] = mapped_column(
        Enum(
            LLMRole,
            name="llm_role",
            native_enum=True,
            values_callable=_enum_values,
        ),
        nullable=False,
    )
    provider: Mapped[LLMProvider] = mapped_column(
        Enum(
            LLMProvider,
            name="llm_provider",
            native_enum=True,
            values_callable=_enum_values,
        ),
        nullable=False,
    )
    model_name: Mapped[str] = mapped_column(String(255), nullable=False)
    base_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    api_key_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    api_key_provider: Mapped[LLMProvider | None] = mapped_column(
        Enum(
            LLMProvider,
            name="llm_provider",
            native_enum=True,
            values_callable=_enum_values,
            create_constraint=False,
        ),
        nullable=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    user: Mapped["User"] = relationship(back_populates="llm_role_settings")
