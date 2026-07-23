from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel
from sqlalchemy.engine import make_url

load_dotenv()


class Settings(BaseModel):
    app_name: str = "ShadowLedger API"
    environment: str = "development"
    debug: bool = False
    database_url: str = "postgresql+asyncpg://shadowledger:shadowledger@localhost:5432/shadowledger"
    frontend_origin: str = "http://localhost:4200"
    demo_auth_enabled: bool = False
    allow_insecure_target_endpoints: bool = False
    allow_private_target_endpoints: bool = False


@lru_cache
def get_settings() -> Settings:
    raw_database_url = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://shadowledger:shadowledger@localhost:5432/shadowledger",
    )
    environment = os.getenv("ENVIRONMENT", "development")

    return Settings(
        app_name=os.getenv("APP_NAME", "ShadowLedger API"),
        environment=environment,
        debug=_environment_flag("DEBUG"),
        database_url=_normalize_database_url(raw_database_url, environment),
        frontend_origin=os.getenv("FRONTEND_ORIGIN", "http://localhost:4200"),
        demo_auth_enabled=_environment_flag("NEXT_PUBLIC_DEMO_AUTH"),
        allow_insecure_target_endpoints=_environment_flag("ALLOW_INSECURE_TARGET_ENDPOINTS"),
        allow_private_target_endpoints=_environment_flag("ALLOW_PRIVATE_TARGET_ENDPOINTS"),
    )


def _normalize_database_url(database_url: str, environment: str) -> str:
    try:
        parsed_url = make_url(database_url)
    except Exception:
        return database_url

    if parsed_url.drivername in {"postgres", "postgresql"}:
        parsed_url = parsed_url.set(drivername="postgresql+asyncpg")

    if (
        environment.lower() != "production"
        and not _running_in_docker()
        and parsed_url.host in {"postgres", "db"}
    ):
        parsed_url = parsed_url.set(host="localhost")

    return parsed_url.render_as_string(hide_password=False)


def _running_in_docker() -> bool:
    return Path("/.dockerenv").exists()


def _environment_flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}
