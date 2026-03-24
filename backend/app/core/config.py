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
    debug: bool = True
    database_url: str = "postgresql+asyncpg://shadowledger:shadowledger@localhost:5432/shadowledger"
    frontend_origin: str = "http://localhost:3000"


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
        debug=os.getenv("DEBUG", "true").lower() == "true",
        database_url=_normalize_database_url(raw_database_url, environment),
        frontend_origin=os.getenv("FRONTEND_ORIGIN", "http://localhost:3000"),
    )


def _normalize_database_url(database_url: str, environment: str) -> str:
    if environment.lower() == "production" or _running_in_docker():
        return database_url

    try:
        parsed_url = make_url(database_url)
    except Exception:
        return database_url

    if parsed_url.host not in {"postgres", "db"}:
        return database_url

    return parsed_url.set(host="localhost").render_as_string(hide_password=False)


def _running_in_docker() -> bool:
    return Path("/.dockerenv").exists()
