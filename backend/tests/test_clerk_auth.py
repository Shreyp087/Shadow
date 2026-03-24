from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from auth.clerk import verify_clerk_token


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

