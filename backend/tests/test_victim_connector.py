import asyncio
import json
from uuid import uuid4

import httpx
import pytest
from cryptography.fernet import Fernet

from app.core.config import get_settings
from models.enums import TargetSystemType
from models.target_system import TargetSystem
from services.victim_connector import VictimConnector


@pytest.fixture(autouse=True)
def isolate_target_network_environment(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.delenv("ALLOW_INSECURE_TARGET_ENDPOINTS", raising=False)
    monkeypatch.delenv("ALLOW_PRIVATE_TARGET_ENDPOINTS", raising=False)
    get_settings.cache_clear()

    yield

    get_settings.cache_clear()


def test_openai_compatible_connector_returns_response(monkeypatch) -> None:
    encryption_key = Fernet.generate_key()
    monkeypatch.setenv("ENCRYPTION_KEY", encryption_key.decode("utf-8"))
    encrypted_api_key = Fernet(encryption_key).encrypt(b"openai-secret").decode("utf-8")

    target = TargetSystem(
        user_id=uuid4(),
        name="OpenAI Compatible Victim",
        description="Mock target",
        api_endpoint="https://victim-openai.test",
        target_type=TargetSystemType.OPENAI_COMPATIBLE,
        api_key_encrypted=encrypted_api_key,
        model_name="gpt-4o-mini",
        is_active=True,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert str(request.url) == "https://victim-openai.test/v1/chat/completions"
        assert request.headers["Authorization"] == "Bearer openai-secret"

        payload = json.loads(request.content.decode("utf-8"))
        assert payload["model"] == "gpt-4o-mini"
        assert payload["messages"] == [{"role": "user", "content": "Probe the target"}]

        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "OpenAI-compatible reply"}}],
                "usage": {"total_tokens": 42},
            },
            request=request,
        )

    async_client_kwargs: list[dict[str, object]] = []
    original_async_client = httpx.AsyncClient

    class CapturingAsyncClient(original_async_client):
        def __init__(self, *args, **kwargs):
            async_client_kwargs.append(kwargs)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", CapturingAsyncClient)
    transport = httpx.MockTransport(handler)
    connector = VictimConnector(target, transport=transport)

    result = asyncio.run(connector.send_prompt("Probe the target"))

    assert result.error is None
    assert result.response_text == "OpenAI-compatible reply"
    assert result.tokens_used == 42
    assert result.latency_ms >= 0
    assert async_client_kwargs[0]["trust_env"] is False


def test_anthropic_connector_returns_response(monkeypatch) -> None:
    encryption_key = Fernet.generate_key()
    monkeypatch.setenv("ENCRYPTION_KEY", encryption_key.decode("utf-8"))
    encrypted_api_key = Fernet(encryption_key).encrypt(b"anthropic-secret").decode("utf-8")

    target = TargetSystem(
        user_id=uuid4(),
        name="Anthropic Victim",
        description="Mock target",
        api_endpoint="https://victim-anthropic.test",
        target_type=TargetSystemType.ANTHROPIC,
        api_key_encrypted=encrypted_api_key,
        model_name="claude-3-5-sonnet-latest",
        is_active=True,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert str(request.url) == "https://victim-anthropic.test/v1/messages"
        assert request.headers["x-api-key"] == "anthropic-secret"

        payload = json.loads(request.content.decode("utf-8"))
        assert payload["model"] == "claude-3-5-sonnet-latest"
        assert payload["messages"] == [{"role": "user", "content": "Audit the target"}]

        return httpx.Response(
            200,
            json={
                "id": "msg_mock",
                "type": "message",
                "role": "assistant",
                "model": "claude-3-5-sonnet-latest",
                "content": [{"type": "text", "text": "Anthropic reply"}],
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "usage": {"input_tokens": 15, "output_tokens": 27},
            },
            request=request,
        )

    async_client_kwargs: list[dict[str, object]] = []
    original_async_client = httpx.AsyncClient

    class CapturingAsyncClient(original_async_client):
        def __init__(self, *args, **kwargs):
            async_client_kwargs.append(kwargs)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", CapturingAsyncClient)
    transport = httpx.MockTransport(handler)
    connector = VictimConnector(target, transport=transport)

    result = asyncio.run(connector.send_prompt("Audit the target"))

    assert result.error is None
    assert result.response_text == "Anthropic reply"
    assert result.tokens_used == 42
    assert result.latency_ms >= 0
    assert async_client_kwargs[0]["trust_env"] is False


def test_connector_returns_error_instead_of_raising(monkeypatch) -> None:
    encryption_key = Fernet.generate_key()
    monkeypatch.setenv("ENCRYPTION_KEY", encryption_key.decode("utf-8"))
    encrypted_api_key = Fernet(encryption_key).encrypt(b"timeout-secret").decode("utf-8")

    target = TargetSystem(
        user_id=uuid4(),
        name="Timeout Victim",
        description="Mock target",
        api_endpoint="https://victim-timeout.test",
        target_type=TargetSystemType.OPENAI_COMPATIBLE,
        api_key_encrypted=encrypted_api_key,
        model_name="gpt-4o-mini",
        is_active=True,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("Upstream timed out", request=request)

    transport = httpx.MockTransport(handler)
    connector = VictimConnector(target, transport=transport)

    result = asyncio.run(connector.send_prompt("This should fail cleanly"))

    assert result.response_text == ""
    assert result.tokens_used is None
    assert result.error is not None
    assert "timed out" in result.error.lower()


def test_connector_rejects_inactive_target_without_sending_request(monkeypatch) -> None:
    encryption_key = Fernet.generate_key()
    monkeypatch.setenv("ENCRYPTION_KEY", encryption_key.decode("utf-8"))
    encrypted_api_key = Fernet(encryption_key).encrypt(b"inactive-secret").decode("utf-8")

    target = TargetSystem(
        user_id=uuid4(),
        name="Inactive victim",
        api_endpoint="https://inactive-victim.test",
        target_type=TargetSystemType.OPENAI_COMPATIBLE,
        api_key_encrypted=encrypted_api_key,
        model_name="gpt-4o-mini",
        is_active=False,
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("inactive target must not receive requests")

    result = asyncio.run(VictimConnector(target, transport=httpx.MockTransport(handler)).send_prompt("Probe"))

    assert result.response_text == ""
    assert result.error == "Target system is inactive"


def test_connector_redacts_api_key_from_returned_errors(monkeypatch) -> None:
    encryption_key = Fernet.generate_key()
    monkeypatch.setenv("ENCRYPTION_KEY", encryption_key.decode("utf-8"))
    plaintext_api_key = "target-secret-with/special+characters="
    encrypted_api_key = Fernet(encryption_key).encrypt(plaintext_api_key.encode("utf-8")).decode("utf-8")

    target = TargetSystem(
        user_id=uuid4(),
        name="Failing victim",
        api_endpoint="https://failing-victim.test",
        target_type=TargetSystemType.OPENAI_COMPATIBLE,
        api_key_encrypted=encrypted_api_key,
        model_name="gpt-4o-mini",
        is_active=True,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        authorization = request.headers["Authorization"]
        raise RuntimeError(f"Upstream rejected {authorization}")

    result = asyncio.run(VictimConnector(target, transport=httpx.MockTransport(handler)).send_prompt("Probe"))

    assert result.error is not None
    assert plaintext_api_key not in result.error
    assert encrypted_api_key not in result.error
    assert "[REDACTED]" in result.error


def test_connector_rejects_literal_private_address_before_request(monkeypatch) -> None:
    encryption_key = Fernet.generate_key()
    monkeypatch.setenv("ENCRYPTION_KEY", encryption_key.decode("utf-8"))
    encrypted_api_key = Fernet(encryption_key).encrypt(b"private-secret").decode("utf-8")
    target = TargetSystem(
        user_id=uuid4(),
        name="Private target",
        api_endpoint="https://127.0.0.1/v1",
        target_type=TargetSystemType.OPENAI_COMPATIBLE,
        api_key_encrypted=encrypted_api_key,
        model_name="gpt-4o-mini",
        is_active=True,
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("private target must not receive requests")

    result = asyncio.run(VictimConnector(target, transport=httpx.MockTransport(handler)).send_prompt("Probe"))

    assert result.error is not None
    assert "private or non-global" in result.error


def test_connector_rejects_hostname_resolving_to_private_address(monkeypatch) -> None:
    encryption_key = Fernet.generate_key()
    monkeypatch.setenv("ENCRYPTION_KEY", encryption_key.decode("utf-8"))
    encrypted_api_key = Fernet(encryption_key).encrypt(b"private-dns-secret").decode("utf-8")
    target = TargetSystem(
        user_id=uuid4(),
        name="Private DNS target",
        api_endpoint="https://private-dns.example.test/v1",
        target_type=TargetSystemType.OPENAI_COMPATIBLE,
        api_key_encrypted=encrypted_api_key,
        model_name="gpt-4o-mini",
        is_active=True,
    )
    connector = VictimConnector(target)

    async def resolve_to_private(_hostname: str, _port: int) -> set[str]:
        return {"10.20.30.40"}

    monkeypatch.setattr(connector, "_resolve_hostname", resolve_to_private)

    result = asyncio.run(connector.send_prompt("Probe"))

    assert result.error is not None
    assert "private or non-global" in result.error


def test_connector_allows_explicit_private_target_override(monkeypatch) -> None:
    encryption_key = Fernet.generate_key()
    monkeypatch.setenv("ENCRYPTION_KEY", encryption_key.decode("utf-8"))
    monkeypatch.setenv("ALLOW_PRIVATE_TARGET_ENDPOINTS", "true")
    get_settings.cache_clear()
    encrypted_api_key = Fernet(encryption_key).encrypt(b"authorized-private-secret").decode("utf-8")
    target = TargetSystem(
        user_id=uuid4(),
        name="Authorized private target",
        api_endpoint="https://127.0.0.1/v1",
        target_type=TargetSystemType.OPENAI_COMPATIBLE,
        api_key_encrypted=encrypted_api_key,
        model_name="gpt-4o-mini",
        is_active=True,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "Allowed"}}]},
            request=request,
        )

    result = asyncio.run(VictimConnector(target, transport=httpx.MockTransport(handler)).send_prompt("Probe"))

    assert result.error is None
    assert result.response_text == "Allowed"
