from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.core.config import get_settings
from models.enums import LLMProvider, LLMRole
from models.llm_role_setting import LLMRoleSetting
from models.user import User
from routes import llm_role_settings as settings_route
from schemas.llm_role_setting import UpdateLLMRoleSettingRequest
from services.llm_role_settings import (
    LOCAL_AUTH_PLACEHOLDER,
    load_effective_llm_role_settings,
    resolve_effective_llm_role_setting,
)


class FakeExecuteResult:
    def __init__(self, items: list[LLMRoleSetting]) -> None:
        self._items = items

    def scalars(self) -> "FakeExecuteResult":
        return self

    def all(self) -> list[LLMRoleSetting]:
        return self._items


class FakeSession:
    def __init__(self, items: list[LLMRoleSetting] | None = None) -> None:
        self.items = items or []
        self.scalar_value = self.items[0] if self.items else None
        self.added: list[LLMRoleSetting] = []
        self.commit_calls = 0
        self.refresh_calls = 0

    async def execute(self, _statement) -> FakeExecuteResult:
        return FakeExecuteResult(self.items)

    async def scalar(self, _statement) -> LLMRoleSetting | None:
        return self.scalar_value

    def add(self, obj: LLMRoleSetting) -> None:
        obj.id = obj.id or uuid4()
        obj.created_at = obj.created_at or datetime.now(timezone.utc)
        obj.updated_at = obj.updated_at or datetime.now(timezone.utc)
        self.added.append(obj)

    async def commit(self) -> None:
        self.commit_calls += 1

    async def refresh(self, obj: LLMRoleSetting) -> None:
        self.refresh_calls += 1
        obj.id = obj.id or uuid4()
        obj.created_at = obj.created_at or datetime.now(timezone.utc)
        obj.updated_at = datetime.now(timezone.utc)


@pytest.fixture(autouse=True)
def isolate_llm_settings_environment(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_ATTACKER_MODEL", raising=False)
    monkeypatch.delenv("OPENAI_MUTATION_MODEL", raising=False)
    monkeypatch.delenv("OPENAI_SCORER_MODEL", raising=False)
    get_settings.cache_clear()

    yield

    get_settings.cache_clear()


def test_get_returns_all_three_legacy_environment_defaults_without_secrets(monkeypatch) -> None:
    async def run_test() -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-environment-secret")
        monkeypatch.setenv("OPENAI_ATTACKER_MODEL", "hosted-attacker")
        monkeypatch.setenv("OPENAI_MUTATION_MODEL", "hosted-mutator")
        monkeypatch.setenv("OPENAI_SCORER_MODEL", "hosted-judge")
        user = User(id=uuid4(), clerk_user_id="clerk_123", email="user@example.test")
        db_session = FakeSession()
        monkeypatch.setattr(
            settings_route,
            "_get_authenticated_user",
            AsyncMock(return_value=user),
        )

        response = await settings_route.list_llm_role_settings(
            db_session=db_session,
            clerk_user_id="clerk_123",
        )

        assert response.data is not None
        assert [item.role for item in response.data] == list(LLMRole)
        assert [item.model_name for item in response.data] == [
            "hosted-attacker",
            "hosted-mutator",
            "hosted-judge",
        ]
        assert all(item.provider is LLMProvider.HOSTED_OPENAI for item in response.data)
        assert all(item.api_key_configured for item in response.data)
        assert all(item.is_default for item in response.data)
        assert "sk-environment-secret" not in response.model_dump_json()

    asyncio.run(run_test())


def test_put_encrypts_new_key_and_never_returns_it(monkeypatch) -> None:
    async def run_test() -> None:
        user = User(id=uuid4(), clerk_user_id="clerk_123", email="user@example.test")
        db_session = FakeSession()
        observed_plaintext: list[str] = []
        monkeypatch.setattr(
            settings_route,
            "_get_mutating_user",
            AsyncMock(return_value=user),
        )

        def fake_encrypt(value: str) -> str:
            observed_plaintext.append(value)
            return "encrypted-provider-secret"

        monkeypatch.setattr(settings_route, "encrypt_value", fake_encrypt)

        response = await settings_route.update_llm_role_setting(
            role=LLMRole.JUDGE,
            payload=UpdateLLMRoleSettingRequest(
                provider=LLMProvider.HOSTED_OPENAI,
                model_name="gpt-5.6-terra",
                api_key="sk-provider-secret",
            ),
            db_session=db_session,
            clerk_user_id="clerk_123",
        )

        assert observed_plaintext == ["sk-provider-secret"]
        assert db_session.commit_calls == 1
        stored = db_session.added[0]
        assert stored.api_key_encrypted == "encrypted-provider-secret"
        assert stored.api_key_provider is LLMProvider.HOSTED_OPENAI
        assert response.data is not None
        assert response.data.api_key_configured is True
        assert "sk-provider-secret" not in response.model_dump_json()
        assert "encrypted-provider-secret" not in response.model_dump_json()

    asyncio.run(run_test())


def test_put_without_key_preserves_existing_encrypted_credential(monkeypatch) -> None:
    async def run_test() -> None:
        user = User(id=uuid4(), clerk_user_id="clerk_123", email="user@example.test")
        setting = _stored_setting(user, role=LLMRole.ATTACKER)
        db_session = FakeSession([setting])
        monkeypatch.setattr(
            settings_route,
            "_get_mutating_user",
            AsyncMock(return_value=user),
        )
        encrypt_mock = AsyncMock()
        monkeypatch.setattr(settings_route, "encrypt_value", encrypt_mock)

        await settings_route.update_llm_role_setting(
            role=LLMRole.ATTACKER,
            payload=UpdateLLMRoleSettingRequest(
                provider=LLMProvider.HOSTED_OPENAI,
                model_name="updated-model",
            ),
            db_session=db_session,
            clerk_user_id="clerk_123",
        )

        assert setting.api_key_encrypted == "encrypted-old-secret"
        assert setting.api_key_provider is LLMProvider.HOSTED_OPENAI
        assert setting.model_name == "updated-model"
        encrypt_mock.assert_not_called()

    asyncio.run(run_test())


def test_provider_switch_does_not_forward_retained_hosted_credential(monkeypatch) -> None:
    async def run_test() -> None:
        user = User(id=uuid4(), clerk_user_id="clerk_123", email="user@example.test")
        setting = _stored_setting(user, role=LLMRole.MUTATOR)
        db_session = FakeSession([setting])
        monkeypatch.setattr(
            settings_route,
            "_get_mutating_user",
            AsyncMock(return_value=user),
        )

        response = await settings_route.update_llm_role_setting(
            role=LLMRole.MUTATOR,
            payload=UpdateLLMRoleSettingRequest(
                provider=LLMProvider.LOCAL_OPENAI_COMPATIBLE,
                model_name="mistralai/ministral-3-14b-reasoning",
                base_url="http://127.0.0.1:1234/v1",
            ),
            db_session=db_session,
            clerk_user_id="clerk_123",
        )

        assert setting.api_key_encrypted == "encrypted-old-secret"
        assert setting.api_key_provider is LLMProvider.HOSTED_OPENAI
        effective = resolve_effective_llm_role_setting(LLMRole.MUTATOR, setting)
        assert effective.api_key.get_secret_value() == LOCAL_AUTH_PLACEHOLDER
        assert response.data is not None
        assert response.data.api_key_configured is False

    asyncio.run(run_test())


def test_provider_switch_to_hosted_rejects_missing_matching_or_environment_key(
    monkeypatch,
) -> None:
    async def run_test() -> None:
        user = User(id=uuid4(), clerk_user_id="clerk_123", email="user@example.test")
        setting = _stored_setting(user, role=LLMRole.ATTACKER)
        setting.provider = LLMProvider.LOCAL_OPENAI_COMPATIBLE
        setting.model_name = "local-model"
        setting.base_url = "http://127.0.0.1:1234/v1"
        setting.api_key_provider = LLMProvider.LOCAL_OPENAI_COMPATIBLE
        db_session = FakeSession([setting])
        monkeypatch.setattr(
            settings_route,
            "_get_mutating_user",
            AsyncMock(return_value=user),
        )

        with pytest.raises(HTTPException) as exc_info:
            await settings_route.update_llm_role_setting(
                role=LLMRole.ATTACKER,
                payload=UpdateLLMRoleSettingRequest(
                    provider=LLMProvider.HOSTED_OPENAI,
                    model_name="gpt-4o-mini",
                ),
                db_session=db_session,
                clerk_user_id="clerk_123",
            )

        assert exc_info.value.status_code == 409
        assert "API key is required" in exc_info.value.detail
        assert db_session.commit_calls == 0

    asyncio.run(run_test())


def test_provider_switch_back_to_hosted_reuses_retained_hosted_key(monkeypatch) -> None:
    async def run_test() -> None:
        user = User(id=uuid4(), clerk_user_id="clerk_123", email="user@example.test")
        setting = _stored_setting(user, role=LLMRole.JUDGE)
        setting.provider = LLMProvider.LOCAL_OPENAI_COMPATIBLE
        setting.model_name = "local-model"
        setting.base_url = "http://127.0.0.1:1234/v1"
        # The encrypted key remains bound to Hosted after an earlier switch.
        setting.api_key_provider = LLMProvider.HOSTED_OPENAI
        db_session = FakeSession([setting])
        monkeypatch.setattr(
            settings_route,
            "_get_mutating_user",
            AsyncMock(return_value=user),
        )

        response = await settings_route.update_llm_role_setting(
            role=LLMRole.JUDGE,
            payload=UpdateLLMRoleSettingRequest(
                provider=LLMProvider.HOSTED_OPENAI,
                model_name="gpt-4o-mini",
            ),
            db_session=db_session,
            clerk_user_id="clerk_123",
        )

        assert db_session.commit_calls == 1
        assert response.data is not None
        assert response.data.api_key_configured is True

    asyncio.run(run_test())


def test_effective_loader_decrypts_role_bound_keys(monkeypatch) -> None:
    async def run_test() -> None:
        user_id = uuid4()
        settings = [
            _stored_setting(
                User(id=user_id, clerk_user_id="clerk_123", email="user@example.test"),
                role=role,
            )
            for role in LLMRole
        ]
        db_session = FakeSession(settings)
        monkeypatch.setattr(
            "services.llm_role_settings.decrypt_value",
            lambda _ciphertext: "decrypted-secret",
        )

        effective = await load_effective_llm_role_settings(db_session, user_id)

        assert set(effective) == set(LLMRole)
        assert all(
            value.api_key.get_secret_value() == "decrypted-secret"
            for value in effective.values()
        )

    asyncio.run(run_test())


def test_local_provider_is_development_only_and_loopback_only(monkeypatch) -> None:
    with pytest.raises(ValidationError, match="localhost"):
        UpdateLLMRoleSettingRequest(
            provider=LLMProvider.LOCAL_OPENAI_COMPATIBLE,
            model_name="local-model",
            base_url="http://192.168.1.25:1234/v1",
        )

    monkeypatch.setenv("ENVIRONMENT", "production")
    get_settings.cache_clear()
    with pytest.raises(ValidationError, match="development-only"):
        UpdateLLMRoleSettingRequest(
            provider=LLMProvider.LOCAL_OPENAI_COMPATIBLE,
            model_name="local-model",
            base_url="http://127.0.0.1:1234/v1",
        )


@pytest.mark.parametrize(
    "base_url",
    [
        "http://localhost:1234/v1",
        "http://127.0.0.1:1234/v1/chat/completions",
        "http://[::1]:1234/v1",
    ],
)
def test_local_provider_accepts_only_safe_loopback_forms(base_url: str) -> None:
    payload = UpdateLLMRoleSettingRequest(
        provider=LLMProvider.LOCAL_OPENAI_COMPATIBLE,
        model_name="local-model",
        base_url=base_url,
    )

    assert payload.base_url is not None


@pytest.mark.parametrize(
    "base_url",
    [
        "http://user:password@127.0.0.1:1234/v1",
        "http://127.0.0.1:1234/v1?api_key=unsafe",
        "http://127.0.0.1:1234/v1#fragment",
    ],
)
def test_local_provider_rejects_url_embedded_secrets(base_url: str) -> None:
    with pytest.raises(ValidationError):
        UpdateLLMRoleSettingRequest(
            provider=LLMProvider.LOCAL_OPENAI_COMPATIBLE,
            model_name="local-model",
            base_url=base_url,
        )


def test_url_validation_error_does_not_echo_api_key() -> None:
    with pytest.raises(ValidationError) as exc_info:
        UpdateLLMRoleSettingRequest(
            provider=LLMProvider.LOCAL_OPENAI_COMPATIBLE,
            model_name="local-model",
            base_url="https://external.example.test/v1",
            api_key="sentinel-secret-must-not-leak",
        )

    serialized_error = exc_info.value.json()
    assert "sentinel-secret-must-not-leak" not in serialized_error
    assert "external.example.test" in serialized_error


def test_request_secret_is_masked_and_blank_value_means_preserve() -> None:
    payload = UpdateLLMRoleSettingRequest(
        provider=LLMProvider.HOSTED_OPENAI,
        model_name="gpt-4o-mini",
        api_key="sk-sensitive",
    )
    preserve_payload = UpdateLLMRoleSettingRequest(
        provider=LLMProvider.HOSTED_OPENAI,
        model_name="gpt-4o-mini",
        api_key="   ",
    )

    assert payload.api_key is not None
    assert payload.api_key.get_secret_value() == "sk-sensitive"
    assert "sk-sensitive" not in repr(payload)
    assert "sk-sensitive" not in payload.model_dump_json()
    assert preserve_payload.api_key is None


def test_chat_probe_posts_minimal_completion_and_requires_content(monkeypatch) -> None:
    async def run_test() -> None:
        observed: dict[str, object] = {}

        class FakeResponse:
            def raise_for_status(self) -> None:
                return None

            def json(self) -> dict:
                return {"choices": [{"message": {"content": "OK"}}]}

        class FakeClient:
            def __init__(self, **kwargs: object) -> None:
                observed["client_options"] = kwargs

            async def __aenter__(self) -> "FakeClient":
                return self

            async def __aexit__(self, *_args: object) -> None:
                return None

            async def post(self, url: str, **kwargs: object) -> FakeResponse:
                observed["url"] = url
                observed["request"] = kwargs
                return FakeResponse()

        monkeypatch.setattr(settings_route.httpx, "AsyncClient", FakeClient)

        ok, message = await settings_route._probe_chat_completion(
            provider=LLMProvider.LOCAL_OPENAI_COMPATIBLE,
            base_url="http://127.0.0.1:1234/v1",
            api_key="local-test-key",
            model_name="mistralai/ministral-3-14b-reasoning",
        )

        assert ok is True
        assert message == "Chat completion succeeded with the configured model"
        assert observed["url"] == "http://127.0.0.1:1234/v1/chat/completions"
        request = observed["request"]
        assert isinstance(request, dict)
        assert request["json"]["model"] == "mistralai/ministral-3-14b-reasoning"
        assert request["json"]["max_tokens"] == 32
        assert request["headers"]["Authorization"] == "Bearer local-test-key"
        assert observed["client_options"]["follow_redirects"] is False
        assert observed["client_options"]["trust_env"] is False
        assert observed["client_options"]["timeout"].connect == 180.0

    asyncio.run(run_test())


def test_chat_probe_rejects_non_chat_or_empty_response(monkeypatch) -> None:
    async def run_test() -> None:
        class FakeResponse:
            def raise_for_status(self) -> None:
                return None

            def json(self) -> dict:
                return {"data": [{"id": "text-embedding-model"}]}

        class FakeClient:
            def __init__(self, **_kwargs: object) -> None:
                pass

            async def __aenter__(self) -> "FakeClient":
                return self

            async def __aexit__(self, *_args: object) -> None:
                return None

            async def post(self, _url: str, **_kwargs: object) -> FakeResponse:
                return FakeResponse()

        monkeypatch.setattr(settings_route.httpx, "AsyncClient", FakeClient)

        ok, message = await settings_route._probe_chat_completion(
            provider=LLMProvider.LOCAL_OPENAI_COMPATIBLE,
            base_url="http://127.0.0.1:1234/v1",
            api_key="local-test-key",
            model_name="text-embedding-model",
        )

        assert ok is False
        assert "no chat content" in message

    asyncio.run(run_test())


def test_chat_probe_sanitizes_provider_http_error(monkeypatch) -> None:
    async def run_test() -> None:
        class FakeClient:
            def __init__(self, **_kwargs: object) -> None:
                pass

            async def __aenter__(self) -> "FakeClient":
                return self

            async def __aexit__(self, *_args: object) -> None:
                return None

            async def post(self, url: str, **_kwargs: object):
                request = httpx.Request("POST", url)
                return httpx.Response(
                    401,
                    request=request,
                    text="upstream leaked sk-do-not-return-this",
                )

        monkeypatch.setattr(settings_route.httpx, "AsyncClient", FakeClient)

        ok, message = await settings_route._probe_chat_completion(
            provider=LLMProvider.HOSTED_OPENAI,
            base_url="https://api.openai.com/v1",
            api_key="sk-do-not-return-this",
            model_name="hosted-model",
        )

        assert ok is False
        assert message == "Provider returned HTTP 401"
        assert "sk-do-not-return-this" not in message

    asyncio.run(run_test())


def test_connection_test_route_uses_saved_role_and_returns_no_secret(monkeypatch) -> None:
    async def run_test() -> None:
        user = User(id=uuid4(), clerk_user_id="clerk_123", email="user@example.test")
        setting = LLMRoleSetting(
            id=uuid4(),
            user_id=user.id,
            role=LLMRole.JUDGE,
            provider=LLMProvider.LOCAL_OPENAI_COMPATIBLE,
            model_name="mistralai/ministral-3-14b-reasoning",
            base_url="http://127.0.0.1:1234/v1",
            api_key_encrypted="encrypted-local-secret",
            api_key_provider=LLMProvider.LOCAL_OPENAI_COMPATIBLE,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db_session = FakeSession([setting])
        monkeypatch.setattr(
            settings_route,
            "_get_authenticated_user",
            AsyncMock(return_value=user),
        )
        monkeypatch.setattr(
            "services.llm_role_settings.decrypt_value",
            lambda _ciphertext: "decrypted-local-secret",
        )
        probe = AsyncMock(return_value=(True, "Chat completion succeeded"))
        monkeypatch.setattr(settings_route, "_probe_chat_completion", probe)

        response = await settings_route.test_llm_role_setting(
            role=LLMRole.JUDGE,
            db_session=db_session,
            clerk_user_id="clerk_123",
        )

        probe.assert_awaited_once_with(
            provider=LLMProvider.LOCAL_OPENAI_COMPATIBLE,
            base_url="http://127.0.0.1:1234/v1",
            api_key="decrypted-local-secret",
            model_name="mistralai/ministral-3-14b-reasoning",
        )
        assert response.data is not None
        assert response.data.ok is True
        assert response.data.role is LLMRole.JUDGE
        assert "decrypted-local-secret" not in response.model_dump_json()
        assert "encrypted-local-secret" not in response.model_dump_json()

    asyncio.run(run_test())


def _stored_setting(user: User, *, role: LLMRole) -> LLMRoleSetting:
    return LLMRoleSetting(
        id=uuid4(),
        user_id=user.id,
        role=role,
        provider=LLMProvider.HOSTED_OPENAI,
        model_name="gpt-4o-mini",
        base_url="https://api.openai.com/v1",
        api_key_encrypted="encrypted-old-secret",
        api_key_provider=LLMProvider.HOSTED_OPENAI,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
