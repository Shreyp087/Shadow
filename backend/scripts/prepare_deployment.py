"""Run additive schema migrations and reference-vector seeding in Vercel builds."""
import asyncio
import os
import sys
from pathlib import Path

os.environ["PYTHON_DOTENV_DISABLED"] = "1"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main():
    if not os.getenv("DATABASE_URL", "").strip():
        print("Database setup skipped: DATABASE_URL is not configured.")
        return
    # Schema setup uses the integration's direct connection. App requests keep
    # the pooled DATABASE_URL supplied by Vercel in their separate processes.
    direct_url = os.getenv("DATABASE_URL_UNPOOLED") or os.getenv("POSTGRES_URL_NON_POOLING")
    if direct_url:
        os.environ["DATABASE_URL"] = direct_url
    from alembic import command
    from alembic.config import Config
    from seeds.run_seeds import main as seed_vectors
    from app.core.deployment import database_failure_reason
    from app.core.config import get_settings
    from sqlalchemy.engine import make_url
    if os.getenv("VERCEL") == "1" and make_url(get_settings().database_url).host in {
        "localhost", "127.0.0.1", "::1", "postgres", "db",
    }:
        print("Database setup pending: connect a hosted PostgreSQL database in Vercel.")
        return
    try:
        command.upgrade(Config("alembic.ini"), "head")
        asyncio.run(seed_vectors())
    except Exception as exc:
        print(f"Database deployment setup failed ({type(exc).__name__}: {database_failure_reason(exc)}).", file=sys.stderr)
        raise SystemExit(1) from None
    print("Database migrations and reference vectors are ready.")


if __name__ == "__main__":
    main()
