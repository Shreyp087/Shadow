from __future__ import annotations

from collections.abc import AsyncGenerator

from fastapi.testclient import TestClient
from sqlalchemy import text

from app.db.session import get_db_session
from app.main import app


class HealthySession:
    async def execute(self, statement) -> None:
        compiled = str(statement)
        assert "SELECT 1" in compiled or statement == text("SELECT 1")


class FailingSession:
    async def execute(self, _statement) -> None:
        raise RuntimeError("db unavailable")


def test_healthcheck_reports_connected_database() -> None:
    async def override_session() -> AsyncGenerator[HealthySession, None]:
        yield HealthySession()

    app.dependency_overrides[get_db_session] = override_session
    client = TestClient(app)

    response = client.get("/health")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": "1.0.0", "db": "connected"}


def test_healthcheck_reports_database_errors() -> None:
    async def override_session() -> AsyncGenerator[FailingSession, None]:
        yield FailingSession()

    app.dependency_overrides[get_db_session] = override_session
    client = TestClient(app)

    response = client.get("/health")

    app.dependency_overrides.clear()

    assert response.status_code == 503
    assert response.json() == {"status": "ok", "version": "1.0.0", "db": "error"}


def test_api_responses_include_no_store_security_headers() -> None:
    async def override_session() -> AsyncGenerator[HealthySession, None]:
        yield HealthySession()

    app.dependency_overrides[get_db_session] = override_session
    client = TestClient(app)

    response = client.get("/api/health")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
