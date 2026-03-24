from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import ConfigDict

from .common import ORMResponseModel


class TrustLedgerEntryResponse(ORMResponseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    attack_result_id: UUID
    entry_hash: str
    prev_hash: str | None
    payload_json: dict[str, Any]
    created_at: datetime
