from app.core.config import _normalize_database_url, get_settings
from sqlalchemy.ext.asyncio import create_async_engine


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


def test_managed_postgres_keeps_tls_and_channel_binding_parameters():
    original = "postgresql://test:test@database.test/app?sslmode=require&channel_binding=require"
    normalized = _normalize_database_url(original, "production")
    engine = create_async_engine(normalized)
    _args, kwargs = engine.dialect.create_connect_args(engine.url)
    assert engine.dialect.driver == "psycopg"
    assert kwargs["sslmode"] == "require"
    assert kwargs["channel_binding"] == "require"


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


def test_vercel_defaults_to_production_and_its_public_origin(monkeypatch) -> None:
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.delenv("FRONTEND_ORIGIN", raising=False)
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("VERCEL_ENV", "production")
    monkeypatch.setenv("VERCEL_PROJECT_PRODUCTION_URL", "shadowledger-iota.vercel.app")
    get_settings.cache_clear()
    try:
        settings = get_settings()
        assert settings.environment == "production"
        assert settings.frontend_origin == "https://shadowledger-iota.vercel.app"
    finally:
        get_settings.cache_clear()
