import asyncio
import json
from uuid import uuid4

import httpx
from cryptography.fernet import Fernet

from models.enums import TargetSystemType
from models.target_system import TargetSystem
from services.victim_connector import VictimConnector


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

    transport = httpx.MockTransport(handler)
    connector = VictimConnector(target, transport=transport)

    result = asyncio.run(connector.send_prompt("Probe the target"))

    assert result.error is None
    assert result.response_text == "OpenAI-compatible reply"
    assert result.tokens_used == 42
    assert result.latency_ms >= 0


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

    transport = httpx.MockTransport(handler)
    connector = VictimConnector(target, transport=transport)

    result = asyncio.run(connector.send_prompt("Audit the target"))

    assert result.error is None
    assert result.response_text == "Anthropic reply"
    assert result.tokens_used == 42
    assert result.latency_ms >= 0


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
