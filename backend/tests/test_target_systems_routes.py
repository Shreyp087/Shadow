from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import uuid4
from unittest.mock import AsyncMock

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


def test_list_target_systems_returns_masked_api_key(monkeypatch) -> None:
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
        monkeypatch.setattr(target_systems_route, "decrypt_value", lambda value: "sk-test-1234")

        response = await target_systems_route.list_target_systems(
            db_session=db_session,
            clerk_user_id="clerk_user_123",
        )

        assert response.data is not None
        assert response.data[0].api_key_masked == "****1234"
        assert "api_key_encrypted" not in response.data[0].model_dump()

    asyncio.run(run_test())


def test_create_target_system_returns_masked_api_key(monkeypatch) -> None:
    async def run_test() -> None:
        user = User(id=uuid4(), clerk_user_id="clerk_user_123", email="user@example.com")
        db_session = FakeSession()

        monkeypatch.setattr(
            target_systems_route,
            "_get_mutating_user",
            AsyncMock(return_value=user),
        )
        monkeypatch.setattr(target_systems_route, "encrypt_value", lambda value: "encrypted-secret")
        monkeypatch.setattr(target_systems_route, "decrypt_value", lambda value: "sk-live-5678")

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
        assert response.data.api_key_masked == "****5678"
        assert db_session.commit_calls == 1
        assert db_session.refresh_calls == 1
        stored_target = db_session.added[0]
        assert isinstance(stored_target, TargetSystem)
        assert stored_target.api_key_encrypted == "encrypted-secret"

    asyncio.run(run_test())
