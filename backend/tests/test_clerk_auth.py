from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from app.core.config import get_settings
from auth.clerk import DEMO_CLERK_USER_ID, verify_clerk_token
from auth.clerk import _validate_authorized_party


@pytest.fixture(autouse=True)
def isolate_clerk_environment(monkeypatch):
    for key in (
        "CLERK_JWT_KEY",
        "CLERK_JWKS_URL",
        "CLERK_FRONTEND_API_URL",
        "CLERK_ISSUER",
        "CLERK_AUTHORIZED_PARTIES",
        "NEXT_PUBLIC_DEMO_AUTH",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("ENVIRONMENT", "development")
    get_settings.cache_clear()

    yield

    get_settings.cache_clear()


def test_verify_clerk_token_requires_bearer_in_clerk_mode() -> None:
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(verify_clerk_token(None))

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Missing Bearer token"


def test_verify_clerk_token_accepts_explicit_development_demo_mode(monkeypatch) -> None:
    monkeypatch.setenv("NEXT_PUBLIC_DEMO_AUTH", "true")
    get_settings.cache_clear()

    result = asyncio.run(verify_clerk_token(None))

    assert result == DEMO_CLERK_USER_ID


def test_verify_clerk_token_never_enables_demo_in_production(monkeypatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("NEXT_PUBLIC_DEMO_AUTH", "true")
    get_settings.cache_clear()

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(verify_clerk_token(None))

    assert exc_info.value.status_code == 401


def test_verify_clerk_token_returns_subject(monkeypatch) -> None:
    private_key, public_key = _generate_rsa_keypair()
    monkeypatch.setenv("CLERK_JWT_KEY", public_key)
    monkeypatch.setenv("CLERK_AUTHORIZED_PARTIES", "http://localhost:3000")

    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": "user_clerk_123",
            "azp": "http://localhost:3000",
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
        },
        private_key,
        algorithm="RS256",
    )

    result = asyncio.run(
        verify_clerk_token(HTTPAuthorizationCredentials(scheme="Bearer", credentials=token))
    )

    assert result == "user_clerk_123"


def test_verify_clerk_token_rejects_pending_status(monkeypatch) -> None:
    private_key, public_key = _generate_rsa_keypair()
    monkeypatch.setenv("CLERK_JWT_KEY", public_key)
    monkeypatch.setenv("CLERK_AUTHORIZED_PARTIES", "http://localhost:3000")

    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": "user_clerk_123",
            "azp": "http://localhost:3000",
            "sts": "pending",
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
        },
        private_key,
        algorithm="RS256",
    )

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(verify_clerk_token(HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)))

    assert exc_info.value.status_code == 403


def _generate_rsa_keypair() -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


@pytest.mark.parametrize("origin", [
    "https://shadowledger-iota.vercel.app",
    "https://shadowledger-iota.vercel.app/",
    "https://shadowledger-iota.vercel.app:443",
])
def test_production_origin_allows_equivalent_origin_spelling(monkeypatch, origin):
    monkeypatch.setenv("CLERK_AUTHORIZED_PARTIES", " https://shadowledger-iota.vercel.app/ ")
    _validate_authorized_party({"azp": origin})


@pytest.mark.parametrize("origin", [
    "https://untrusted.test",
    "https://shadowledger-iota.vercel.app.untrusted.test",
    "https://shadowledger-iota.vercel.app:444",
    "https://shadowledger-iota.vercel.app/other",
    "https://shadowledger-iota.vercel.app:bad-port",
    "https://user@shadowledger-iota.vercel.app",
])
def test_production_origin_keeps_other_parties_rejected(monkeypatch, origin):
    monkeypatch.setenv("CLERK_AUTHORIZED_PARTIES", "https://shadowledger-iota.vercel.app/")
    with pytest.raises(HTTPException) as error:
        _validate_authorized_party({"azp": origin})
    assert error.value.status_code == 401
