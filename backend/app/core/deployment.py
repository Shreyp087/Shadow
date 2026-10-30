"""Deployment readiness without reading or returning credential values."""

import os


def missing_configuration() -> list[str]:
    required = (
        "DATABASE_URL",
        "ENCRYPTION_KEY",
        "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY",
        "CLERK_SECRET_KEY",
    )
    missing = [name for name in required if not os.getenv(name, "").strip()]
    if not any(os.getenv(name, "").strip() for name in (
        "CLERK_JWT_KEY", "CLERK_JWKS_URL", "CLERK_FRONTEND_API_URL"
    )):
        missing.append("CLERK_JWKS_URL")
    return missing
