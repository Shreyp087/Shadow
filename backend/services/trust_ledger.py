from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.attack_result import AttackResult
from models.trust_ledger_entry import TrustLedgerEntry

GENESIS_HASH = "GENESIS"
CANONICAL_JSON_SEPARATORS = (",", ":")


class TrustLedgerViolationError(RuntimeError):
    pass


@dataclass(slots=True)
class ChainVerificationResult:
    is_valid: bool
    first_broken_entry_id: UUID | None = None


class TrustLedger:
    def __init__(self, db_session: AsyncSession) -> None:
        self.db_session = db_session

    async def append(self, attack_result_id: UUID, payload: dict) -> TrustLedgerEntry:
        self._assert_append_only()

        attack_result = await self._fetch_attack_result(attack_result_id)
        if attack_result is None:
            raise ValueError(f"AttackResult {attack_result_id} was not found")

        latest_entry = await self._fetch_latest_entry()
        prev_hash = latest_entry.entry_hash if latest_entry is not None else GENESIS_HASH
        canonical_payload = self._canonical_payload(payload)
        entry_hash = self._compute_hash(prev_hash, canonical_payload)

        entry = TrustLedgerEntry(
            attack_result_id=attack_result.id,
            entry_hash=entry_hash,
            prev_hash=prev_hash,
            payload_json=json.loads(canonical_payload),
        )
        self.db_session.add(entry)
        await self.db_session.flush()
        return entry

    async def verify_chain(self, from_entry_id: UUID, to_entry_id: UUID) -> ChainVerificationResult:
        self._assert_append_only()

        entries = await self._fetch_all_entries_in_order()
        if not entries:
            return ChainVerificationResult(is_valid=True, first_broken_entry_id=None)

        entry_index = {entry.id: index for index, entry in enumerate(entries)}
        if from_entry_id not in entry_index:
            raise ValueError(f"from_entry_id {from_entry_id} was not found in the trust ledger")
        if to_entry_id not in entry_index:
            raise ValueError(f"to_entry_id {to_entry_id} was not found in the trust ledger")

        start_index = entry_index[from_entry_id]
        end_index = entry_index[to_entry_id]
        if start_index > end_index:
            raise ValueError("from_entry_id must come before or equal to to_entry_id")

        for index in range(start_index, end_index + 1):
            entry = entries[index]
            canonical_payload = self._canonical_payload(entry.payload_json)
            expected_prev_hash = GENESIS_HASH if index == 0 else (
                entry.prev_hash if index == start_index else entries[index - 1].entry_hash
            )
            expected_hash = self._compute_hash(expected_prev_hash, canonical_payload)

            if entry.prev_hash != expected_prev_hash or entry.entry_hash != expected_hash:
                return ChainVerificationResult(is_valid=False, first_broken_entry_id=entry.id)

        return ChainVerificationResult(is_valid=True, first_broken_entry_id=None)

    async def get_entries(self, attack_run_id: UUID) -> list[TrustLedgerEntry]:
        self._assert_append_only()
        return await self._fetch_entries_for_run(attack_run_id)

    async def get_entry_verification_statuses(self, entry_ids: list[UUID]) -> dict[UUID, bool]:
        self._assert_append_only()
        if not entry_ids:
            return {}

        entries = await self._fetch_all_entries_in_order()
        requested_ids = set(entry_ids)
        statuses: dict[UUID, bool] = {}
        previous_requested_entry: TrustLedgerEntry | None = None
        requested_chain_is_valid = True

        for index, entry in enumerate(entries):
            if entry.id not in requested_ids:
                continue

            canonical_payload = self._canonical_payload(entry.payload_json)
            expected_prev_hash = GENESIS_HASH if index == 0 else (
                entry.prev_hash if previous_requested_entry is None else previous_requested_entry.entry_hash
            )
            expected_hash = self._compute_hash(expected_prev_hash, canonical_payload)
            is_valid = (
                requested_chain_is_valid
                and entry.prev_hash == expected_prev_hash
                and entry.entry_hash == expected_hash
            )
            statuses[entry.id] = is_valid

            if not is_valid:
                requested_chain_is_valid = False
            else:
                previous_requested_entry = entry

        missing_ids = requested_ids.difference(statuses)
        if missing_ids:
            missing = ", ".join(str(item) for item in sorted(missing_ids))
            raise ValueError(f"Trust ledger entries were not found: {missing}")

        return statuses

    async def _fetch_attack_result(self, attack_result_id: UUID) -> AttackResult | None:
        return await self.db_session.get(AttackResult, attack_result_id)

    async def _fetch_latest_entry(self) -> TrustLedgerEntry | None:
        statement = (
            select(TrustLedgerEntry)
            .order_by(TrustLedgerEntry.created_at.desc())
            .limit(1)
        )
        result = await self.db_session.execute(statement)
        return result.scalars().first()

    async def _fetch_all_entries_in_order(self) -> list[TrustLedgerEntry]:
        statement = select(TrustLedgerEntry).order_by(TrustLedgerEntry.created_at.asc())
        result = await self.db_session.execute(statement)
        return list(result.scalars().all())

    async def _fetch_entries_for_run(self, attack_run_id: UUID) -> list[TrustLedgerEntry]:
        statement = (
            select(TrustLedgerEntry)
            .join(AttackResult, TrustLedgerEntry.attack_result_id == AttackResult.id)
            .where(AttackResult.attack_run_id == attack_run_id)
            .order_by(TrustLedgerEntry.created_at.asc())
        )
        result = await self.db_session.execute(statement)
        return list(result.scalars().all())

    def _assert_append_only(self) -> None:
        dirty_entries = [item for item in getattr(self.db_session, "dirty", ()) if isinstance(item, TrustLedgerEntry)]
        deleted_entries = [item for item in getattr(self.db_session, "deleted", ()) if isinstance(item, TrustLedgerEntry)]

        if dirty_entries or deleted_entries:
            raise TrustLedgerViolationError("Trust ledger entries are append-only and cannot be updated or deleted")

    @staticmethod
    def _canonical_payload(payload: dict | str) -> str:
        normalized_payload = json.loads(payload) if isinstance(payload, str) else payload
        return json.dumps(normalized_payload, sort_keys=True, separators=CANONICAL_JSON_SEPARATORS)

    @staticmethod
    def _compute_hash(prev_hash: str, canonical_payload: str) -> str:
        return hashlib.sha256(f"{prev_hash}{canonical_payload}".encode("utf-8")).hexdigest()
