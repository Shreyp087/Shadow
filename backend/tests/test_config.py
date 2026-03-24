from app.core.config import _normalize_database_url


def test_normalize_database_url_rewrites_docker_hostname_for_local_development() -> None:
    database_url = "postgresql+asyncpg://shadowledger:shadowledger@postgres:5432/shadowledger"

    normalized = _normalize_database_url(database_url, "development")

    assert normalized == "postgresql+asyncpg://shadowledger:shadowledger@localhost:5432/shadowledger"


def test_normalize_database_url_preserves_non_docker_hosts() -> None:
    database_url = "postgresql+asyncpg://shadowledger:shadowledger@localhost:5432/shadowledger"

    normalized = _normalize_database_url(database_url, "development")

    assert normalized == database_url
