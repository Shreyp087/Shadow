from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import ForeignKey, String, event
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin


class TrustLedgerEntry(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "trust_ledger_entries"

    attack_result_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("attack_results.id"),
        nullable=False,
        index=True,
    )
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)

    attack_result: Mapped["AttackResult"] = relationship(back_populates="trust_ledger_entries")


def _prevent_mutation(*_: object, **__: object) -> None:
    raise ValueError("trust_ledger_entries is append-only and cannot be updated or deleted")


event.listen(TrustLedgerEntry, "before_update", _prevent_mutation, propagate=True)
event.listen(TrustLedgerEntry, "before_delete", _prevent_mutation, propagate=True)

