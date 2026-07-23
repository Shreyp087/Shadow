from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import uuid4
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from app.core.config import get_settings
from models.enums import TargetSystemType
from models.target_system import TargetSystem
from models.user import User
from routes import target_systems as target_systems_route
from schemas.target_system import CreateTargetSystemRequest


class FakeExecuteResult:
    def __init__(self, items: list[TargetSystem]) -> None:
        self._items = items

    def scalars(self) -> "FakeExecuteResult":
        return self

    def all(self) -> list[TargetSystem]:
        return self._items


class FakeSession:
    def __init__(self, items: list[TargetSystem] | None = None) -> None:
        self.items = items or []
        self.added: list[object] = []
        self.commit_calls = 0
        self.refresh_calls = 0

    async def execute(self, _statement):
        return FakeExecuteResult(self.items)

    def add(self, obj: object) -> None:
        if getattr(obj, "id", None) is None:
            obj.id = uuid4()
        if getattr(obj, "created_at", None) is None:
            obj.created_at = datetime.now(timezone.utc)
        self.added.append(obj)

    async def commit(self) -> None:
        self.commit_calls += 1

    async def refresh(self, _obj: object) -> None:
        self.refresh_calls += 1


@pytest.fixture(autouse=True)
def isolate_endpoint_environment(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.delenv("ALLOW_INSECURE_TARGET_ENDPOINTS", raising=False)
    monkeypatch.delenv("ALLOW_PRIVATE_TARGET_ENDPOINTS", raising=False)
    get_settings.cache_clear()

    yield

    get_settings.cache_clear()


def test_list_target_systems_returns_only_api_key_configuration_state(monkeypatch) -> None:
    async def run_test() -> None:
        user = User(id=uuid4(), clerk_user_id="clerk_user_123", email="user@example.com")
        target_system = TargetSystem(
            id=uuid4(),
            user_id=user.id,
            name="GPT-4 Customer Support Bot",
            description="Support assistant",
            api_endpoint="https://example.test/v1/chat/completions",
            target_type=TargetSystemType.OPENAI_COMPATIBLE,
            api_key_encrypted="encrypted-secret",
            model_name="gpt-4o-mini",
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        db_session = FakeSession([target_system])

        monkeypatch.setattr(
            target_systems_route,
            "_get_authenticated_user",
            AsyncMock(return_value=user),
        )

        response = await target_systems_route.list_target_systems(
            db_session=db_session,
            clerk_user_id="clerk_user_123",
        )

        assert response.data is not None
        serialized = response.data[0].model_dump()
        assert response.data[0].api_key_configured is True
        assert "api_key_encrypted" not in serialized
        assert "api_key" not in serialized
        assert "api_key_masked" not in serialized

    asyncio.run(run_test())


def test_create_target_system_accepts_secret_and_returns_configuration_state(monkeypatch) -> None:
    async def run_test() -> None:
        user = User(id=uuid4(), clerk_user_id="clerk_user_123", email="user@example.com")
        db_session = FakeSession()

        monkeypatch.setattr(
            target_systems_route,
            "_get_mutating_user",
            AsyncMock(return_value=user),
        )
        observed_plaintext: list[str] = []

        def fake_encrypt(value: str) -> str:
            observed_plaintext.append(value)
            return "encrypted-secret"

        monkeypatch.setattr(target_systems_route, "encrypt_value", fake_encrypt)

        response = await target_systems_route.create_target_system(
            payload=CreateTargetSystemRequest(
                name="Internal HR Assistant",
                description="HR assistant",
                api_endpoint="https://example.test/messages",
                target_type=TargetSystemType.ANTHROPIC,
                api_key="sk-live-5678",
                model_name="claude-3-5-sonnet",
                is_active=True,
            ),
            db_session=db_session,
            clerk_user_id="clerk_user_123",
        )

        assert response.data is not None
        assert response.data.api_key_configured is True
        assert "sk-live-5678" not in response.data.model_dump_json()
        assert observed_plaintext == ["sk-live-5678"]
        assert db_session.commit_calls == 1
        assert db_session.refresh_calls == 1
        stored_target = db_session.added[0]
        assert isinstance(stored_target, TargetSystem)
        assert stored_target.api_key_encrypted == "encrypted-secret"

    asyncio.run(run_test())


def test_create_target_system_request_hides_secret_value() -> None:
    payload = CreateTargetSystemRequest(
        name="Internal HR Assistant",
        api_endpoint="https://example.test/messages",
        target_type=TargetSystemType.ANTHROPIC,
        api_key="sk-sensitive-value",
        model_name="claude-3-5-sonnet",
    )

    assert payload.api_key.get_secret_value() == "sk-sensitive-value"
    assert "sk-sensitive-value" not in repr(payload)
    assert "sk-sensitive-value" not in payload.model_dump_json()


def test_create_target_system_request_requires_https_by_default() -> None:
    with pytest.raises(ValidationError, match="must use HTTPS"):
        CreateTargetSystemRequest(
            name="Local target",
            api_endpoint="http://localhost:9000/v1",
            target_type=TargetSystemType.OPENAI_COMPATIBLE,
            api_key="local-key",
            model_name="local-model",
        )


def test_create_target_system_request_allows_explicit_development_http_override(monkeypatch) -> None:
    monkeypatch.setenv("ALLOW_INSECURE_TARGET_ENDPOINTS", "true")
    get_settings.cache_clear()

    payload = CreateTargetSystemRequest(
        name="Local target",
        api_endpoint="http://localhost:9000/v1",
        target_type=TargetSystemType.OPENAI_COMPATIBLE,
        api_key="local-key",
        model_name="local-model",
    )

    assert str(payload.api_endpoint) == "http://localhost:9000/v1"


def test_create_target_system_request_rejects_http_override_in_production(monkeypatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("ALLOW_INSECURE_TARGET_ENDPOINTS", "true")
    get_settings.cache_clear()

    with pytest.raises(ValidationError, match="must use HTTPS"):
        CreateTargetSystemRequest(
            name="Local target",
            api_endpoint="http://localhost:9000/v1",
            target_type=TargetSystemType.OPENAI_COMPATIBLE,
            api_key="local-key",
            model_name="local-model",
        )


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://user:password@example.test/v1",
        "https://example.test/v1#secret-fragment",
        "https://example.test/v1?api_key=must-not-be-in-a-url",
    ],
)
def test_create_target_system_request_rejects_endpoint_credentials_and_fragments(endpoint: str) -> None:
    with pytest.raises(ValidationError):
        CreateTargetSystemRequest(
            name="Unsafe target",
            api_endpoint=endpoint,
            target_type=TargetSystemType.OPENAI_COMPATIBLE,
            api_key="target-key",
            model_name="target-model",
        )


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://127.0.0.1/v1",
        "https://10.0.0.5/v1",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/v1",
    ],
)
def test_create_target_system_request_rejects_literal_non_global_addresses(endpoint: str) -> None:
    with pytest.raises(ValidationError, match="private or non-global"):
        CreateTargetSystemRequest(
            name="Unsafe target",
            api_endpoint=endpoint,
            target_type=TargetSystemType.OPENAI_COMPATIBLE,
            api_key="target-key",
            model_name="target-model",
        )


def test_create_target_system_request_allows_explicit_private_target_override(monkeypatch) -> None:
    monkeypatch.setenv("ALLOW_PRIVATE_TARGET_ENDPOINTS", "true")
    get_settings.cache_clear()

    payload = CreateTargetSystemRequest(
        name="Authorized internal target",
        api_endpoint="https://10.0.0.5/v1",
        target_type=TargetSystemType.OPENAI_COMPATIBLE,
        api_key="target-key",
        model_name="target-model",
    )

    assert str(payload.api_endpoint) == "https://10.0.0.5/v1"


def test_create_target_system_request_allows_global_literal_address() -> None:
    payload = CreateTargetSystemRequest(
        name="Public target",
        api_endpoint="https://8.8.8.8/v1",
        target_type=TargetSystemType.OPENAI_COMPATIBLE,
        api_key="target-key",
        model_name="target-model",
    )

    assert str(payload.api_endpoint) == "https://8.8.8.8/v1"
