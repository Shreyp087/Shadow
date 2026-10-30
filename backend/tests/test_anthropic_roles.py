import asyncio
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from anthropic import AsyncAnthropic
from pydantic import SecretStr, ValidationError

from models.enums import LLMRole, LLMProvider
from models.llm_role_setting import LLMRoleSetting
from schemas.llm_role_setting import UpdateLLMRoleSettingRequest, ANTHROPIC_API_BASE_URL
from services.llm_client import request_text
from services.llm_client_factory import create_role_llm_clients
from services.llm_role_settings import resolve_effective_llm_role_setting, LLMSettingsConfigurationError


def test_all_three_roles_use_native_claude_messages_and_independent_clients():
    async def exercise():
        observed = []
        def handler(request):
            assert str(request.url) == "https://api.anthropic.com/v1/messages"
            assert request.headers["x-api-key"] == "test-anthropic-key"
            assert "authorization" not in request.headers
            observed.append(request)
            return httpx.Response(200, json={
                "id": "msg_test", "type": "message", "role": "assistant", "model": "claude-sonnet-4-6",
                "content": [{"type": "text", "text": "OK"}], "stop_reason": "end_turn",
                "stop_sequence": None, "usage": {"input_tokens": 5, "output_tokens": 1},
            })
        def factory(**kwargs):
            return AsyncAnthropic(**kwargs, http_client=httpx.AsyncClient(
                transport=httpx.MockTransport(handler), follow_redirects=False, trust_env=False,
            ))
        settings = {role: SimpleNamespace(
            role=role, provider=LLMProvider.HOSTED_ANTHROPIC, model_name="claude-sonnet-4-6",
            base_url=ANTHROPIC_API_BASE_URL, api_key=SecretStr("test-anthropic-key"),
        ) for role in LLMRole}
        clients = await create_role_llm_clients(settings, anthropic_client_factory=factory)
        try:
            assert len({id(clients.for_role(role.value).client) for role in LLMRole}) == 3
            for role in LLMRole:
                assert await request_text(clients.for_role(role.value).client,
                    model="claude-sonnet-4-6", system_prompt=role.value,
                    user_prompt="Reply with OK.", max_tokens=32) == "OK"
            assert len(observed) == 3
        finally:
            await clients.close()
    asyncio.run(exercise())


def test_switching_to_claude_never_reuses_an_openai_key(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    setting = LLMRoleSetting(
        user_id=uuid4(), role=LLMRole.JUDGE, provider=LLMProvider.HOSTED_ANTHROPIC,
        model_name="claude-sonnet-4-6", base_url=ANTHROPIC_API_BASE_URL,
        api_key_encrypted="old-encrypted-openai-key", api_key_provider=LLMProvider.HOSTED_OPENAI,
    )
    with pytest.raises(LLMSettingsConfigurationError, match="Anthropic"):
        resolve_effective_llm_role_setting(LLMRole.JUDGE, setting)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
    resolved = resolve_effective_llm_role_setting(LLMRole.JUDGE, setting)
    assert resolved.api_key.get_secret_value() == "test-anthropic-key"


def test_claude_roles_work_in_production_but_cannot_override_anthropic_endpoint(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    request = UpdateLLMRoleSettingRequest(provider="hosted_anthropic", model_name="claude-sonnet-4-6")
    assert request.provider == LLMProvider.HOSTED_ANTHROPIC
    with pytest.raises(ValidationError, match="fixed base URL"):
        UpdateLLMRoleSettingRequest(provider="hosted_anthropic", model_name="claude-sonnet-4-6", base_url="https://untrusted.test")
