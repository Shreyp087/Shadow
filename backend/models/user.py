from __future__ import annotations

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin


class User(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "users"

    clerk_user_id: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)

    target_systems: Mapped[list["TargetSystem"]] = relationship(back_populates="user")
    attack_runs: Mapped[list["AttackRun"]] = relationship(back_populates="user")
    llm_role_settings: Mapped[list["LLMRoleSetting"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )
