from __future__ import annotations

import asyncio
from uuid import uuid4
from unittest.mock import AsyncMock

import pytest
from fastapi import BackgroundTasks, HTTPException

from models.attack_result import AttackResult
from models.attack_run import AttackRun
from models.enums import AttackRunStatus, AttackVectorCategory, RiskCategory, TargetSystemType
from models.target_system import TargetSystem
from models.user import User
from routes import attack_runs as attack_runs_route
from schemas.attack_run import CreateAttackRunRequest


class FakeSession:
    def __init__(self) -> None:
        self.added: list[object] = []
        self.commit_calls = 0
        self.refresh_calls = 0
        self.scalar_value = 2
        self.execute_items: list[AttackResult] = []

    def add(self, obj: object) -> None:
        if getattr(obj, "id", None) is None:
            obj.id = uuid4()
        self.added.append(obj)

    async def commit(self) -> None:
        self.commit_calls += 1

    async def refresh(self, obj: object) -> None:
        self.refresh_calls += 1
        if getattr(obj, "id", None) is None:
            obj.id = uuid4()

    async def scalar(self, _statement):
        return self.scalar_value

    async def execute(self, _statement):
        return FakeExecuteResult(self.execute_items)


class FakeExecuteResult:
    def __init__(self, items: list[AttackResult]) -> None:
        self._items = items

    def scalars(self) -> "FakeExecuteResult":
        return self

    def all(self) -> list[AttackResult]:
        return self._items


def test_create_attack_run_returns_pending_response_and_background_task(monkeypatch) -> None:
    async def run_test() -> None:
        db_session = FakeSession()
        user = User(id=uuid4(), clerk_user_id="clerk_user_123", email="user@example.com")
        target_system = TargetSystem(
            id=uuid4(),
            user_id=user.id,
            name="Victim",
            description="Target system",
            api_endpoint="https://victim.test",
            target_type=TargetSystemType.OPENAI_COMPATIBLE,
            api_key_encrypted="encrypted",
            model_name="gpt-4o-mini",
            is_active=True,
        )

        monkeypatch.setattr(
            attack_runs_route,
            "_get_authenticated_user",
            AsyncMock(return_value=user),
        )
        monkeypatch.setattr(
            attack_runs_route,
            "_get_user_target_system",
            AsyncMock(return_value=target_system),
        )
        monkeypatch.setattr(
            attack_runs_route,
            "_resolve_vector_ids",
            AsyncMock(return_value=[uuid4(), uuid4(), uuid4()]),
        )

        payload = CreateAttackRunRequest(
            target_system_id=target_system.id,
            vector_category_filter=[AttackVectorCategory.PROMPT_INJECTION.value],
        )
        background_tasks = BackgroundTasks()

        response = await attack_runs_route.create_attack_run(
            payload=payload,
            background_tasks=background_tasks,
            db_session=db_session,
            clerk_user_id="clerk_user_123",
            openai_api_key="test-openai-key",
        )

        assert response.data is not None
        assert response.data.status == AttackRunStatus.PENDING
        assert response.meta["vector_count"] == 3
        assert len(background_tasks.tasks) == 1
        assert db_session.commit_calls == 1

    asyncio.run(run_test())


def test_parse_vector_categories_rejects_invalid_values() -> None:
    with pytest.raises(HTTPException) as exc_info:
        attack_runs_route._parse_vector_categories(["PROMPT_INJECTION", "not-real"])

    assert exc_info.value.status_code == 422


def test_download_attack_run_report_returns_pdf_response(monkeypatch) -> None:
    async def run_test() -> None:
        db_session = FakeSession()
        user = User(id=uuid4(), clerk_user_id="clerk_user_123", email="user@example.com")
        attack_run = AttackRun(
            id=uuid4(),
            target_system_id=uuid4(),
            user_id=user.id,
            status=AttackRunStatus.COMPLETED,
            total_attacks=8,
            vulnerabilities_found=2,
            risk_score_avg=61,
        )

        monkeypatch.setattr(
            attack_runs_route,
            "_get_authenticated_user",
            AsyncMock(return_value=user),
        )
        monkeypatch.setattr(
            attack_runs_route,
            "_get_user_attack_run",
            AsyncMock(return_value=attack_run),
        )

        class FakeReportGenerator:
            async def generate_audit_report(self, attack_run_id, session):
                assert attack_run_id == attack_run.id
                assert session is db_session
                return b"%PDF-1.7 fake report"

        monkeypatch.setattr(attack_runs_route, "ReportGenerator", FakeReportGenerator)

        response = await attack_runs_route.download_attack_run_report(
            run_id=attack_run.id,
            db_session=db_session,
            clerk_user_id="clerk_user_123",
        )

        assert response.media_type == "application/pdf"
        assert response.body.startswith(b"%PDF")
        assert "attachment;" in response.headers["content-disposition"]
        assert str(attack_run.id) in response.headers["content-disposition"]

    asyncio.run(run_test())
