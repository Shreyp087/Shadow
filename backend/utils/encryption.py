from __future__ import annotations

import os

from cryptography.fernet import Fernet, InvalidToken


def encrypt_value(value: str) -> str:
    return _get_fernet().encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_value(value: str) -> str:
    try:
        return _get_fernet().decrypt(value.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("Unable to decrypt value with the configured ENCRYPTION_KEY") from exc


def _get_fernet() -> Fernet:
    key = os.getenv("ENCRYPTION_KEY")
    if not key:
        raise ValueError("ENCRYPTION_KEY is not set")

    try:
        return Fernet(key.encode("utf-8"))
    except Exception as exc:
        raise ValueError("ENCRYPTION_KEY is invalid for Fernet") from exc

