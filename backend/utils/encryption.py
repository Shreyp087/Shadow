from __future__ import annotations

import os

from cryptography.fernet import Fernet, InvalidToken, MultiFernet


def encrypt_value(value: str) -> str:
    return _get_fernet().encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_value(value: str) -> str:
    try:
        return _get_fernet().decrypt(value.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("Unable to decrypt value with the configured ENCRYPTION_KEY") from exc


def rotate_value(value: str) -> str:
    fernet = _get_fernet()
    encoded_value = value.encode("utf-8")

    try:
        if isinstance(fernet, MultiFernet):
            return fernet.rotate(encoded_value).decode("utf-8")

        fernet.decrypt(encoded_value)
        return value
    except InvalidToken as exc:
        raise ValueError("Unable to rotate value with the configured encryption keys") from exc


def _get_fernet() -> Fernet | MultiFernet:
    primary_key = os.getenv("ENCRYPTION_KEY", "").strip()
    if not primary_key:
        raise ValueError("ENCRYPTION_KEY is not set")

    previous_keys = [
        key.strip()
        for key in os.getenv("ENCRYPTION_KEY_PREVIOUS", "").split(",")
        if key.strip()
    ]

    try:
        fernets = [Fernet(key.encode("utf-8")) for key in [primary_key, *previous_keys]]
    except Exception as exc:
        raise ValueError("An encryption key is invalid for Fernet") from exc

    return fernets[0] if len(fernets) == 1 else MultiFernet(fernets)
