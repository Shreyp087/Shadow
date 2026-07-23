from app.core.config import _normalize_database_url, get_settings


def test_normalize_database_url_rewrites_docker_hostname_for_local_development() -> None:
    database_url = "postgresql+asyncpg://shadowledger:shadowledger@postgres:5432/shadowledger"

    normalized = _normalize_database_url(database_url, "development")

    assert normalized == "postgresql+asyncpg://shadowledger:shadowledger@localhost:5432/shadowledger"


def test_normalize_database_url_preserves_non_docker_hosts() -> None:
    database_url = "postgresql+asyncpg://shadowledger:shadowledger@localhost:5432/shadowledger"

    normalized = _normalize_database_url(database_url, "development")

    assert normalized == database_url


def test_normalize_database_url_adds_asyncpg_driver_to_managed_database_url() -> None:
    database_url = "postgresql://shadowledger:secret@database.example.com:5432/shadowledger"

    normalized = _normalize_database_url(database_url, "production")

    assert normalized == (
        "postgresql+asyncpg://shadowledger:secret@database.example.com:5432/shadowledger"
    )


def test_settings_default_to_debug_disabled(monkeypatch) -> None:
    monkeypatch.delenv("DEBUG", raising=False)
    get_settings.cache_clear()

    try:
        assert get_settings().debug is False
    finally:
        get_settings.cache_clear()


def test_settings_read_shared_demo_auth_flag(monkeypatch) -> None:
    monkeypatch.setenv("NEXT_PUBLIC_DEMO_AUTH", "true")
    get_settings.cache_clear()

    try:
        assert get_settings().demo_auth_enabled is True
    finally:
        get_settings.cache_clear()


def test_settings_default_private_target_override_to_disabled(monkeypatch) -> None:
    monkeypatch.delenv("ALLOW_PRIVATE_TARGET_ENDPOINTS", raising=False)
    get_settings.cache_clear()

    try:
        assert get_settings().allow_private_target_endpoints is False
    finally:
        get_settings.cache_clear()
