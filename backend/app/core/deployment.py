"""Deployment readiness without reading or returning credential values."""

import os


def database_failure_reason(error: Exception) -> str:
    """Return a fixed diagnostic label, never raw connection error text."""
    message = str(error).lower()
    for pattern, reason in (
        ("password authentication failed", "database_authentication_failed"),
        ("invalid password", "database_authentication_failed"),
        ("could not translate host", "database_dns_failed"),
        ("name or service not known", "database_dns_failed"),
        ("connection refused", "database_connection_refused"),
        ("unexpected keyword", "unsupported_database_url_option"),
        ("invalid connection option", "unsupported_database_url_option"),
        ("channel binding", "database_channel_binding_failed"),
        ("ssl", "database_tls_failed"),
        ("timeout", "database_connection_timed_out"),
        ("timed out", "database_connection_timed_out"),
    ):
        if pattern in message:
            return reason
    return "database_connection_failed"


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
