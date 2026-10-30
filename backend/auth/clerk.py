from __future__ import annotations

import os
from functools import lru_cache
from typing import Any
from urllib.parse import urlsplit

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient
from starlette.concurrency import run_in_threadpool

from app.core.config import get_settings

bearer_scheme = HTTPBearer(auto_error=False)
DEMO_CLERK_USER_ID = "demo_shadowledger_host"


async def verify_clerk_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> str:
    if demo_auth_enabled():
        return DEMO_CLERK_USER_ID

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Bearer token",
        )

    token = credentials.credentials

    try:
        payload = await run_in_threadpool(_decode_clerk_jwt, token)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid Clerk token: {_error_message(exc)}",
        ) from exc

    if payload.get("sts") == "pending":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Clerk session status is pending",
        )

    clerk_user_id = payload.get("sub") or payload.get("user_id")
    if not isinstance(clerk_user_id, str) or not clerk_user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Clerk token missing subject",
        )

    _validate_authorized_party(payload)
    return clerk_user_id


def _decode_clerk_jwt(token: str) -> dict[str, Any]:
    header = jwt.get_unverified_header(token)
    algorithm = header.get("alg")
    if algorithm != "RS256":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unsupported Clerk JWT algorithm",
        )

    verification_key = _get_verification_key(token)
    decode_kwargs: dict[str, Any] = {
        "algorithms": ["RS256"],
        "options": {"verify_aud": False},
    }

    issuer = _configured_env_value("CLERK_ISSUER")
    if issuer:
        decode_kwargs["issuer"] = issuer

    return jwt.decode(token, verification_key, **decode_kwargs)


def _get_verification_key(token: str) -> Any:
    jwt_key = _configured_env_value("CLERK_JWT_KEY")
    if jwt_key:
        return jwt_key

    jwk_client = _get_jwk_client(_resolve_jwks_url())
    return jwk_client.get_signing_key_from_jwt(token).key


def _validate_authorized_party(payload: dict[str, Any]) -> None:
    azp = payload.get("azp")
    allowed_parties = _authorized_parties()

    normalized_azp = _normalized_origin(azp) if azp else ""
    if azp and allowed_parties and (not normalized_azp or normalized_azp not in allowed_parties):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Clerk authorized party",
        )


def _authorized_parties() -> list[str]:
    configured = _configured_env_value("CLERK_AUTHORIZED_PARTIES")
    if configured:
        return [_normalized_origin(item) for item in configured.split(",") if item.strip()]

    frontend_origin = get_settings().frontend_origin
    return [_normalized_origin(frontend_origin)] if frontend_origin else []


def _normalized_origin(value: str) -> str:
    if not isinstance(value, str):
        return ""
    value = value.strip()
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return ""
    # Normalize only origin spelling; never accept a wildcard, path, or userinfo.
    if (
        parsed.scheme in {"http", "https"}
        and parsed.hostname
        and parsed.username is None
        and parsed.password is None
        and parsed.path in {"", "/"}
        and not parsed.query
        and not parsed.fragment
    ):
        host = parsed.hostname.lower()
        if ":" in host:
            host = f"[{host}]"
        suffix = f":{port}" if port and port != (443 if parsed.scheme == "https" else 80) else ""
        return f"{parsed.scheme}://{host}{suffix}"
    return ""


def _resolve_jwks_url() -> str:
    jwks_url = _configured_env_value("CLERK_JWKS_URL")
    if jwks_url:
        return jwks_url

    frontend_api_url = _configured_env_value("CLERK_FRONTEND_API_URL")
    if frontend_api_url:
        return f"{frontend_api_url.rstrip('/')}/.well-known/jwks.json"

    return "https://api.clerk.com/v1/jwks"


def demo_auth_enabled() -> bool:
    settings = get_settings()
    return settings.environment.lower() == "development" and settings.demo_auth_enabled


def _configured_env_value(key: str) -> str | None:
    value = os.getenv(key, "").strip()
    if not value:
        return None

    normalized = value.lower()
    placeholder_fragments = (
        "your-domain",
        "your_clerk",
        "your-clerk",
        "your_jwt",
        "your-jwt",
        "replace-me",
        "example.com",
    )
    if any(fragment in normalized for fragment in placeholder_fragments):
        return None

    return value


@lru_cache(maxsize=4)
def _get_jwk_client(jwks_url: str) -> PyJWKClient:
    return PyJWKClient(jwks_url)


def _error_message(exc: Exception) -> str:
    message = str(exc).strip()
    return message or exc.__class__.__name__
