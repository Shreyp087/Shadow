from __future__ import annotations

import asyncio
from types import SimpleNamespace
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
from services.llm_role_settings import LLMSettingsConfigurationError


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


@pytest.mark.parametrize("execution", ["local", "vercel", "queue_failure"])
def test_create_attack_run_returns_pending_response_and_background_task(monkeypatch, execution) -> None:
    async def run_test() -> None:
        monkeypatch.setenv("VERCEL", "0" if execution == "local" else "1")
        if execution != "local":
            from vercel import workflow
            dispatch = AsyncMock(
                return_value=SimpleNamespace(run_id="workflow-123"),
                side_effect=RuntimeError("queue unavailable") if execution == "queue_failure" else None,
            )
            monkeypatch.setattr(workflow, "start", dispatch)
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
        monkeypatch.setattr(
            attack_runs_route,
            "load_effective_llm_role_settings",
            AsyncMock(return_value={}),
        )

        payload = CreateAttackRunRequest(
            target_system_id=target_system.id,
            vector_category_filter=[AttackVectorCategory.PROMPT_INJECTION.value],
        )
        background_tasks = BackgroundTasks()

        request = attack_runs_route.create_attack_run(
            payload=payload,
            background_tasks=background_tasks,
            db_session=db_session,
            clerk_user_id="clerk_user_123",
        )

        if execution == "queue_failure":
            with pytest.raises(HTTPException) as error:
                await request
            assert error.value.status_code == 503
            assert db_session.added[0].status == AttackRunStatus.FAILED
            assert background_tasks.tasks == []
            return
        response = await request
        assert response.data is not None
        assert response.data.status == AttackRunStatus.PENDING
        assert response.meta["vector_count"] == 3
        assert len(background_tasks.tasks) == (1 if execution == "local" else 0)
        if execution == "vercel":
            assert response.meta["workflow_run_id"] == "workflow-123"
            assert dispatch.await_args.args[1] == str(response.data.id)
        assert db_session.commit_calls == 1

    asyncio.run(run_test())


def test_parse_vector_categories_rejects_invalid_values() -> None:
    with pytest.raises(HTTPException) as exc_info:
        attack_runs_route._parse_vector_categories(["PROMPT_INJECTION", "not-real"])

    assert exc_info.value.status_code == 422


def test_create_attack_run_rejects_unusable_role_settings_before_persisting(monkeypatch) -> None:
    async def run_test() -> None:
        db_session = FakeSession()
        user = User(id=uuid4(), clerk_user_id="clerk_user_123", email="user@example.com")
        target_system = TargetSystem(
            id=uuid4(),
            user_id=user.id,
            name="Victim",
            api_endpoint="https://victim.test",
            target_type=TargetSystemType.OPENAI_COMPATIBLE,
            api_key_encrypted="encrypted",
            model_name="gpt-4o-mini",
            is_active=True,
        )
        monkeypatch.setattr(attack_runs_route, "_get_authenticated_user", AsyncMock(return_value=user))
        monkeypatch.setattr(
            attack_runs_route,
            "_get_user_target_system",
            AsyncMock(return_value=target_system),
        )
        monkeypatch.setattr(
            attack_runs_route,
            "_resolve_vector_ids",
            AsyncMock(return_value=[uuid4()]),
        )
        monkeypatch.setattr(
            attack_runs_route,
            "load_effective_llm_role_settings",
            AsyncMock(
                side_effect=LLMSettingsConfigurationError(
                    "No API key is configured for the judge hosted OpenAI role"
                )
            ),
        )

        with pytest.raises(HTTPException) as exc_info:
            await attack_runs_route.create_attack_run(
                payload=CreateAttackRunRequest(target_system_id=target_system.id),
                background_tasks=BackgroundTasks(),
                db_session=db_session,
                clerk_user_id="clerk_user_123",
            )

        assert exc_info.value.status_code == 409
        assert "judge" in exc_info.value.detail
        assert db_session.added == []
        assert db_session.commit_calls == 0

    asyncio.run(run_test())


def test_background_scan_loads_per_user_settings_and_wires_independent_roles(monkeypatch) -> None:
    async def run_test() -> None:
        user_id = uuid4()
        attack_run = AttackRun(
            id=uuid4(),
            target_system_id=uuid4(),
            user_id=user_id,
            status=AttackRunStatus.PENDING,
            total_attacks=0,
            vulnerabilities_found=0,
        )
        target_system = TargetSystem(
            id=attack_run.target_system_id,
            user_id=user_id,
            name="Victim",
            api_endpoint="https://victim.test",
            target_type=TargetSystemType.OPENAI_COMPATIBLE,
            api_key_encrypted="encrypted",
            model_name="victim-model",
            is_active=True,
        )

        class BackgroundSession:
            async def get(self, model: type, identifier):
                if model is AttackRun and identifier == attack_run.id:
                    return attack_run
                if model is TargetSystem and identifier == target_system.id:
                    return target_system
                return None

            async def commit(self) -> None:
                return None

        session = BackgroundSession()

        class SessionContext:
            async def __aenter__(self):
                return session

            async def __aexit__(self, *_: object) -> None:
                return None

        attacker_llm = object()
        mutator_llm = object()
        judge_llm = object()

        class FakeRoleClients:
            def __init__(self) -> None:
                self.close_calls = 0
                self.roles = {
                    "attacker": SimpleNamespace(client=attacker_llm, model_name="local-attacker"),
                    "mutator": SimpleNamespace(client=mutator_llm, model_name="local-mutator"),
                    "judge": SimpleNamespace(client=judge_llm, model_name="hosted-judge"),
                }

            def for_role(self, role: str):
                return self.roles[role]

            async def close(self) -> None:
                self.close_calls += 1

        role_clients = FakeRoleClients()
        effective_settings = {"settings": "per-user"}
        load_settings = AsyncMock(return_value=effective_settings)
        create_clients = AsyncMock(return_value=role_clients)
        captured: dict[str, object] = {}

        class FakeAttackerAgent:
            def __init__(self, **kwargs: object) -> None:
                captured.update(kwargs)

            async def run_full_scan(self, run_id, target, vector_ids) -> None:
                captured["run"] = (run_id, target, vector_ids)

        monkeypatch.setattr(attack_runs_route, "AsyncSessionLocal", lambda: SessionContext())
        monkeypatch.setattr(attack_runs_route, "load_effective_llm_role_settings", load_settings)
        monkeypatch.setattr(attack_runs_route, "create_role_llm_clients", create_clients)
        monkeypatch.setattr(attack_runs_route, "AttackerAgent", FakeAttackerAgent)
        monkeypatch.setattr(attack_runs_route, "VictimConnector", lambda target: SimpleNamespace(target=target))

        vector_ids = [uuid4(), uuid4()]
        await attack_runs_route._execute_attack_run_background(
            attack_run.id,
            target_system.id,
            vector_ids,
        )

        load_settings.assert_awaited_once_with(session, user_id)
        create_clients.assert_awaited_once_with(effective_settings)
        assert captured["llm_client"] is attacker_llm
        assert captured["model_name"] == "local-attacker"
        assert captured["mutation_engine"].llm_client is mutator_llm
        assert captured["mutation_engine"].model_name == "local-mutator"
        assert captured["scorer_service"].llm_client is judge_llm
        assert captured["scorer_service"].model_name == "hosted-judge"
        assert captured["run"] == (attack_run.id, target_system, vector_ids)
        assert role_clients.close_calls == 1

    asyncio.run(run_test())


def test_get_user_target_system_rejects_inactive_target() -> None:
    async def run_test() -> None:
        db_session = FakeSession()
        user = User(id=uuid4(), clerk_user_id="clerk_user_123", email="user@example.com")
        db_session.scalar_value = TargetSystem(
            id=uuid4(),
            user_id=user.id,
            name="Paused victim",
            api_endpoint="https://victim.test",
            target_type=TargetSystemType.OPENAI_COMPATIBLE,
            api_key_encrypted="encrypted",
            model_name="gpt-4o-mini",
            is_active=False,
        )

        with pytest.raises(HTTPException) as exc_info:
            await attack_runs_route._get_user_target_system(
                db_session,
                user,
                db_session.scalar_value.id,
            )

        assert exc_info.value.status_code == 409
        assert exc_info.value.detail == "Target system is inactive"

    asyncio.run(run_test())


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
