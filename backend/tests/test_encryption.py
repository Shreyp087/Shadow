from cryptography.fernet import Fernet

from utils.encryption import decrypt_value, encrypt_value, rotate_value


def test_encrypt_and_decrypt_with_primary_key(monkeypatch) -> None:
    primary_key = Fernet.generate_key().decode("utf-8")
    monkeypatch.setenv("ENCRYPTION_KEY", primary_key)
    monkeypatch.delenv("ENCRYPTION_KEY_PREVIOUS", raising=False)

    encrypted = encrypt_value("target-provider-secret")

    assert encrypted != "target-provider-secret"
    assert decrypt_value(encrypted) == "target-provider-secret"


def test_previous_key_can_decrypt_during_rotation(monkeypatch) -> None:
    previous_key = Fernet.generate_key()
    encrypted = Fernet(previous_key).encrypt(b"rotating-secret").decode("utf-8")
    primary_key = Fernet.generate_key().decode("utf-8")

    monkeypatch.setenv("ENCRYPTION_KEY", primary_key)
    monkeypatch.setenv("ENCRYPTION_KEY_PREVIOUS", previous_key.decode("utf-8"))

    assert decrypt_value(encrypted) == "rotating-secret"

    newly_encrypted = encrypt_value("new-secret")
    assert Fernet(primary_key.encode("utf-8")).decrypt(newly_encrypted.encode("utf-8")) == b"new-secret"


def test_rotate_value_reencrypts_with_primary_key(monkeypatch) -> None:
    previous_key = Fernet.generate_key()
    primary_key = Fernet.generate_key()
    encrypted_with_previous = Fernet(previous_key).encrypt(b"credential-to-rotate").decode("utf-8")

    monkeypatch.setenv("ENCRYPTION_KEY", primary_key.decode("utf-8"))
    monkeypatch.setenv("ENCRYPTION_KEY_PREVIOUS", previous_key.decode("utf-8"))

    rotated = rotate_value(encrypted_with_previous)

    assert rotated != encrypted_with_previous
    assert Fernet(primary_key).decrypt(rotated.encode("utf-8")) == b"credential-to-rotate"

    monkeypatch.delenv("ENCRYPTION_KEY_PREVIOUS")
    assert decrypt_value(rotated) == "credential-to-rotate"
