from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest

from models.enums import TargetSystemType
from models.target_system import TargetSystem
from models.user import User
from seeds import demo_data


class FakeScalarsResult:
    def __init__(self, items: list[TargetSystem]) -> None:
        self._items = items

    def scalars(self) -> "FakeScalarsResult":
        return self

    def all(self) -> list[TargetSystem]:
        return self._items


class FakeSession:
    def __init__(self, items: list[TargetSystem] | None = None) -> None:
        self.items = items or []
        self.added: list[TargetSystem] = []

    async def execute(self, _statement) -> FakeScalarsResult:
        return FakeScalarsResult(self.items)

    def add(self, target: TargetSystem) -> None:
        target.id = target.id or uuid4()
        self.added.append(target)

    async def flush(self) -> None:
        return None


def test_demo_seed_requires_configured_encryption_key(monkeypatch) -> None:
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)

    with pytest.raises(ValueError, match="valid ENCRYPTION_KEY"):
        demo_data._require_demo_encryption_key()


def test_demo_seed_creates_presentation_targets_inactive(monkeypatch) -> None:
    async def run_test() -> None:
        session = FakeSession()
        user = User(id=uuid4(), clerk_user_id=demo_data.DEMO_CLERK_USER_ID, email="demo@example.com")
        monkeypatch.setattr(demo_data, "encrypt_value", lambda value: f"encrypted:{value}")

        targets = await demo_data._get_or_create_target_systems(session, user)

        assert set(targets) == {demo_data.SUPPORT_TARGET_NAME, demo_data.HR_TARGET_NAME}
        assert all(not target.is_active for target in targets.values())
        assert all(".shadowledger.demo" in target.api_endpoint for target in targets.values())

    asyncio.run(run_test())


def test_demo_seed_deactivates_existing_presentation_target(monkeypatch) -> None:
    async def run_test() -> None:
        user = User(id=uuid4(), clerk_user_id=demo_data.DEMO_CLERK_USER_ID, email="demo@example.com")
        existing = TargetSystem(
            id=uuid4(),
            user_id=user.id,
            name=demo_data.HR_TARGET_NAME,
            api_endpoint="https://old.example.test",
            target_type=TargetSystemType.ANTHROPIC,
            api_key_encrypted="old-encrypted-key",
            model_name="old-model",
            is_active=True,
        )
        session = FakeSession([existing])
        monkeypatch.setattr(demo_data, "encrypt_value", lambda value: f"encrypted:{value}")

        targets = await demo_data._get_or_create_target_systems(session, user)

        assert targets[demo_data.HR_TARGET_NAME] is existing
        assert existing.is_active is False
        assert existing.api_endpoint.endswith(".shadowledger.demo/v1/messages")
        assert all(not target.is_active for target in targets.values())

    asyncio.run(run_test())
