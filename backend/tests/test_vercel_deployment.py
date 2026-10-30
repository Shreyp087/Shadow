import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID, uuid4, uuid5

import pytest
from fastapi.testclient import TestClient

from app.db.session import get_db_session
from app.main import app
from app.workflows import scans
from app.workflows import scan_steps
from app.workflows import scan_runtime
from models.attack_result import AttackResult
from models.enums import AttackRunStatus, RiskCategory


def test_unconfigured_deployment_has_status_without_database_or_credentials(monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    for name in (
        "DATABASE_URL", "ENCRYPTION_KEY", "CLERK_SECRET_KEY", "CLERK_JWT_KEY",
        "CLERK_JWKS_URL", "CLERK_FRONTEND_API_URL", "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    client = TestClient(app)
    response = client.get("/api/status")
    assert response.status_code == 200
    assert response.json()["status"] == "configuration_required"
    assert "DATABASE_URL" in response.json()["missing_configuration"]
    assert response.json()["scan_execution"] == "vercel_workflow"
    response = client.get("/api/v1/attack-runs/")
    assert response.status_code == 503
    assert response.headers["cache-control"] == "no-store"
    assert client.get("/health").json()["db"] == "not_configured"


def test_workflow_keeps_mutations_and_reprioritizes_after_five_attempts(monkeypatch):
    async def exercise():
        monkeypatch.setattr(scans, "begin_scan", AsyncMock(return_value=True))
        attempt = AsyncMock(side_effect=[True, False, False, False, False, False])
        monkeypatch.setattr(scans, "execute_attempt", attempt)
        monkeypatch.setattr(scans, "mutation_prompts", AsyncMock(return_value=["a", "b", "c"]))
        reorder = AsyncMock(side_effect=lambda _run, remaining, _all: list(reversed(remaining)))
        monkeypatch.setattr(scans, "reorder_vectors", reorder)
        finish = AsyncMock()
        monkeypatch.setattr(scans, "finish_scan", finish)
        assert await scans.attack_scan.func("run", ["one", "two", "three"]) == "completed"
        assert attempt.await_count == 6
        assert [call.args[2] for call in attempt.await_args_list[:4]] == [
            "base", "mutation-0", "mutation-1", "mutation-2"
        ]
        reorder.assert_awaited_once()
        finish.assert_awaited_once_with("run", succeeded=True)
    asyncio.run(exercise())


def test_exhausted_workflow_step_marks_scan_failed(monkeypatch):
    async def exercise():
        monkeypatch.setattr(scans, "begin_scan", AsyncMock(return_value=True))
        monkeypatch.setattr(scans, "execute_attempt", AsyncMock(side_effect=RuntimeError("timeout")))
        finish = AsyncMock()
        monkeypatch.setattr(scans, "finish_scan", finish)
        with pytest.raises(RuntimeError):
            await scans.attack_scan.func("run", ["vector"])
        finish.assert_awaited_once_with("run", succeeded=False)
    asyncio.run(exercise())


def test_redelivered_attempt_does_not_call_provider_or_commit_twice(monkeypatch):
    async def exercise():
        run_id, vector_id = str(uuid4()), str(uuid4())
        run = SimpleNamespace(id=uuid4(), status=AttackRunStatus.RUNNING)
        expected_id = uuid5(UUID(run_id), f"{vector_id}:base")
        result = SimpleNamespace(id=expected_id, risk_category=RiskCategory.HIGH)
        saved = {}
        session = SimpleNamespace(scalar=AsyncMock(return_value=run), get=AsyncMock(), commit=AsyncMock())
        async def get(model, identifier):
            if model is AttackResult:
                assert identifier == expected_id
                return saved.get(identifier)
            return SimpleNamespace(is_active=True)
        session.get.side_effect = get
        @asynccontextmanager
        async def context():
            yield session
        monkeypatch.setattr(scan_runtime, "AsyncSessionLocal", context)
        async def attack(*args, **kwargs):
            assert kwargs["result_id"] == expected_id
            saved[expected_id] = result
            return result
        agent = SimpleNamespace(
            run_attack_vector=AsyncMock(side_effect=attack),
            _should_mutate=lambda result: result.risk_category == RiskCategory.HIGH,
        )
        @asynccontextmanager
        async def provider(*args):
            yield agent
        monkeypatch.setattr(scan_runtime, "configured_agent", provider)
        assert await scan_steps.execute_attempt.func(run_id, vector_id, "base") is True
        assert await scan_steps.execute_attempt.func(run_id, vector_id, "base") is True
        agent.run_attack_vector.assert_awaited_once()
        session.commit.assert_awaited_once()
    asyncio.run(exercise())


def test_workflow_does_not_record_provider_error_bodies(monkeypatch):
    async def exercise():
        session = SimpleNamespace(get=AsyncMock(return_value=SimpleNamespace(is_active=True, user_id="owner")))
        run = SimpleNamespace(target_system_id=uuid4(), user_id="owner")
        monkeypatch.setattr(scan_runtime, "load_effective_llm_role_settings", AsyncMock(side_effect=ValueError("secret-value")))
        with pytest.raises(RuntimeError, match="Scan operation failed") as error:
            async with scan_runtime.configured_agent(session, run):
                pass
        assert "secret-value" not in str(error.value)
    asyncio.run(exercise())


def test_cold_workflow_import_works_in_real_vercel_sandbox():
    import importlib
    from vercel.workflow._internal.py_sandbox import Sandbox
    sandbox = Sandbox()
    with sandbox.enter():
        module = importlib.import_module("app.workflows.scans")
        assert module.attack_scan
        assert "sqlalchemy" not in sandbox.table
        assert "app.workflows.scan_runtime" not in sandbox.table
        assert "httpx" not in sandbox.table
