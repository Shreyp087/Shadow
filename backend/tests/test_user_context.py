from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.core.config import get_settings
from auth.clerk import DEMO_CLERK_USER_ID
from models.user import User
from routes._user_context import resolve_request_user


class FakeSession:
    def __init__(self, scalar_values: list[User | None]) -> None:
        self.scalar_values = scalar_values
        self.scalar_calls = 0
        self.added: list[User] = []
        self.flush_calls = 0

    async def scalar(self, _statement) -> User | None:
        self.scalar_calls += 1
        return self.scalar_values.pop(0)

    def add(self, user: User) -> None:
        user.id = user.id or uuid4()
        self.added.append(user)

    async def flush(self) -> None:
        self.flush_calls += 1


@pytest.fixture(autouse=True)
def isolate_auth_mode(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.delenv("NEXT_PUBLIC_DEMO_AUTH", raising=False)
    get_settings.cache_clear()

    yield

    get_settings.cache_clear()


def test_first_clerk_read_creates_isolated_user_without_demo_fallback() -> None:
    async def run_test() -> None:
        demo_user = User(
            id=uuid4(),
            clerk_user_id=DEMO_CLERK_USER_ID,
            email="demo@example.com",
        )
        session = FakeSession([None, demo_user])

        resolved = await resolve_request_user(session, "clerk_user_without_data")

        assert resolved.clerk_user_id == "clerk_user_without_data"
        assert resolved is not demo_user
        assert session.added == [resolved]
        assert session.flush_calls == 1
        assert session.scalar_calls == 1

    asyncio.run(run_test())


def test_demo_identity_is_rejected_when_demo_auth_is_disabled() -> None:
    async def run_test() -> None:
        session = FakeSession([])

        with pytest.raises(HTTPException) as exc_info:
            await resolve_request_user(session, DEMO_CLERK_USER_ID)

        assert exc_info.value.status_code == 401
        assert session.scalar_calls == 0

    asyncio.run(run_test())


def test_demo_identity_resolves_only_in_explicit_demo_mode(monkeypatch) -> None:
    async def run_test() -> None:
        demo_user = User(
            id=uuid4(),
            clerk_user_id=DEMO_CLERK_USER_ID,
            email="demo@example.com",
        )
        session = FakeSession([demo_user])
        monkeypatch.setenv("NEXT_PUBLIC_DEMO_AUTH", "true")
        get_settings.cache_clear()

        resolved = await resolve_request_user(session, DEMO_CLERK_USER_ID)

        assert resolved is demo_user
        assert session.scalar_calls == 1

    asyncio.run(run_test())
