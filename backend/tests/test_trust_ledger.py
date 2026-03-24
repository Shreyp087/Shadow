from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from models.attack_result import AttackResult
from models.enums import RiskCategory
from models.trust_ledger_entry import TrustLedgerEntry
from services.trust_ledger import GENESIS_HASH, TrustLedger, TrustLedgerViolationError


class FakeExecuteResult:
    def __init__(self, items: list[TrustLedgerEntry]) -> None:
        self._items = items

    def scalars(self) -> "FakeExecuteResult":
        return self

    def first(self) -> TrustLedgerEntry | None:
        return self._items[0] if self._items else None

    def all(self) -> list[TrustLedgerEntry]:
        return self._items


class FakeTrustLedgerSession:
    def __init__(self, attack_results: list[AttackResult]) -> None:
        self.attack_results = {item.id: item for item in attack_results}
        self.entries: list[TrustLedgerEntry] = []
        self.dirty: set[object] = set()
        self.deleted: set[object] = set()
        self.flush_calls = 0

    def add(self, obj: object) -> None:
        if isinstance(obj, TrustLedgerEntry):
            if getattr(obj, "id", None) is None:
                obj.id = uuid4()
            if getattr(obj, "created_at", None) is None:
                obj.created_at = datetime.now(timezone.utc) + timedelta(microseconds=len(self.entries))
            self.entries.append(obj)

    async def flush(self) -> None:
        self.flush_calls += 1

    async def get(self, model: type, ident):
        if model is AttackResult:
            return self.attack_results.get(ident)
        return None

    async def execute(self, _statement):
        ordered_entries = sorted(self.entries, key=lambda item: (item.created_at, item.id))
        return FakeExecuteResult(ordered_entries)


class InMemoryTrustLedger(TrustLedger):
    async def _fetch_latest_entry(self) -> TrustLedgerEntry | None:
        if not self.db_session.entries:
            return None
        return sorted(self.db_session.entries, key=lambda item: item.created_at, reverse=True)[0]

    async def _fetch_all_entries_in_order(self) -> list[TrustLedgerEntry]:
        return sorted(self.db_session.entries, key=lambda item: item.created_at)

    async def _fetch_entries_for_run(self, attack_run_id):
        return [
            entry
            for entry in await self._fetch_all_entries_in_order()
            if self.db_session.attack_results[entry.attack_result_id].attack_run_id == attack_run_id
        ]


def build_attack_result(attack_run_id):
    return AttackResult(
        id=uuid4(),
        attack_run_id=attack_run_id,
        attack_vector_id=uuid4(),
        prompt_sent="test prompt",
        response_received="test response",
        risk_score=0,
        is_mutation=False,
        risk_category=RiskCategory.SAFE,
        risk_reason="pending",
    )


def test_append_creates_genesis_and_next_hash_entries() -> None:
    async def run_test() -> None:
        attack_run_id = uuid4()
        first_result = build_attack_result(attack_run_id)
        second_result = build_attack_result(attack_run_id)
        session = FakeTrustLedgerSession([first_result, second_result])
        ledger = InMemoryTrustLedger(session)

        first_entry = await ledger.append(first_result.id, {"risk": "low", "score": 12})
        second_entry = await ledger.append(second_result.id, {"risk": "high", "score": 71})

        assert first_entry.prev_hash == GENESIS_HASH
        assert len(first_entry.entry_hash) == 64
        assert second_entry.prev_hash == first_entry.entry_hash
        assert second_entry.entry_hash != first_entry.entry_hash
        assert session.flush_calls == 2

    asyncio.run(run_test())


def test_verify_chain_returns_valid_for_clean_entries() -> None:
    async def run_test() -> None:
        attack_run_id = uuid4()
        first_result = build_attack_result(attack_run_id)
        second_result = build_attack_result(attack_run_id)
        session = FakeTrustLedgerSession([first_result, second_result])
        ledger = InMemoryTrustLedger(session)

        first_entry = await ledger.append(first_result.id, {"step": 1})
        second_entry = await ledger.append(second_result.id, {"step": 2})
        verification = await ledger.verify_chain(first_entry.id, second_entry.id)

        assert verification.is_valid is True
        assert verification.first_broken_entry_id is None

    asyncio.run(run_test())


def test_verify_chain_accepts_subrange_that_starts_mid_chain() -> None:
    async def run_test() -> None:
        attack_run_id = uuid4()
        first_result = build_attack_result(uuid4())
        second_result = build_attack_result(attack_run_id)
        third_result = build_attack_result(attack_run_id)
        session = FakeTrustLedgerSession([first_result, second_result, third_result])
        ledger = InMemoryTrustLedger(session)

        await ledger.append(first_result.id, {"step": 0, "scope": "other-run"})
        second_entry = await ledger.append(second_result.id, {"step": 1, "scope": "target-run"})
        third_entry = await ledger.append(third_result.id, {"step": 2, "scope": "target-run"})
        verification = await ledger.verify_chain(second_entry.id, third_entry.id)

        assert verification.is_valid is True
        assert verification.first_broken_entry_id is None

    asyncio.run(run_test())


def test_verify_chain_detects_tampered_payload() -> None:
    async def run_test() -> None:
        attack_run_id = uuid4()
        first_result = build_attack_result(attack_run_id)
        second_result = build_attack_result(attack_run_id)
        session = FakeTrustLedgerSession([first_result, second_result])
        ledger = InMemoryTrustLedger(session)

        first_entry = await ledger.append(first_result.id, {"step": 1})
        second_entry = await ledger.append(second_result.id, {"step": 2, "status": "ok"})
        second_entry.payload_json = {"step": 2, "status": "tampered"}

        verification = await ledger.verify_chain(first_entry.id, second_entry.id)

        assert verification.is_valid is False
        assert verification.first_broken_entry_id == second_entry.id

    asyncio.run(run_test())


def test_verify_chain_accepts_payloads_with_different_whitespace_formatting() -> None:
    async def run_test() -> None:
        attack_run_id = uuid4()
        first_result = build_attack_result(attack_run_id)
        second_result = build_attack_result(attack_run_id)
        session = FakeTrustLedgerSession([first_result, second_result])
        ledger = InMemoryTrustLedger(session)

        first_entry = await ledger.append(first_result.id, {"score": 12, "risk": "low"})
        second_entry = await ledger.append(second_result.id, {"status": "ok", "step": 2})
        second_entry.payload_json = '{"status": "ok", "step": 2}'

        verification = await ledger.verify_chain(first_entry.id, second_entry.id)

        assert verification.is_valid is True
        assert verification.first_broken_entry_id is None

    asyncio.run(run_test())


def test_get_entry_verification_statuses_accept_mid_chain_requested_entries() -> None:
    async def run_test() -> None:
        attack_run_id = uuid4()
        first_result = build_attack_result(uuid4())
        second_result = build_attack_result(attack_run_id)
        third_result = build_attack_result(attack_run_id)
        session = FakeTrustLedgerSession([first_result, second_result, third_result])
        ledger = InMemoryTrustLedger(session)

        await ledger.append(first_result.id, {"step": 0, "scope": "other-run"})
        second_entry = await ledger.append(second_result.id, {"step": 1, "scope": "target-run"})
        third_entry = await ledger.append(third_result.id, {"step": 2, "scope": "target-run"})

        statuses = await ledger.get_entry_verification_statuses([second_entry.id, third_entry.id])

        assert statuses == {
            second_entry.id: True,
            third_entry.id: True,
        }

    asyncio.run(run_test())


def test_get_entries_filters_by_attack_run() -> None:
    async def run_test() -> None:
        attack_run_id = uuid4()
        other_run_id = uuid4()
        first_result = build_attack_result(attack_run_id)
        second_result = build_attack_result(other_run_id)
        session = FakeTrustLedgerSession([first_result, second_result])
        ledger = InMemoryTrustLedger(session)

        first_entry = await ledger.append(first_result.id, {"scope": "run-a"})
        await ledger.append(second_result.id, {"scope": "run-b"})

        entries = await ledger.get_entries(attack_run_id)

        assert [entry.id for entry in entries] == [first_entry.id]

    asyncio.run(run_test())


def test_append_raises_violation_when_mutation_attempt_detected() -> None:
    async def run_test() -> None:
        attack_run_id = uuid4()
        attack_result = build_attack_result(attack_run_id)
        session = FakeTrustLedgerSession([attack_result])
        ledger = InMemoryTrustLedger(session)
        existing_entry = await ledger.append(attack_result.id, {"scope": "initial"})
        session.dirty.add(existing_entry)

        with pytest.raises(TrustLedgerViolationError):
            await ledger.append(attack_result.id, {"scope": "should-fail"})

    asyncio.run(run_test())
