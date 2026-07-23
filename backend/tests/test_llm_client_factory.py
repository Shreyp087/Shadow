from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import Enum

import pytest
from pydantic import SecretStr

import services.llm_client_factory as client_factory_module
from services.llm_client_factory import (
    HOSTED_OPENAI_BASE_URL,
    LLMClientConfigurationError,
    LLMClientFactoryOptions,
    create_role_llm_clients,
)


class Role(str, Enum):
    ATTACKER = "attacker"
    MUTATOR = "mutator"
    JUDGE = "judge"


class Provider(str, Enum):
    HOSTED = "hosted_openai"
    LOCAL = "local_openai_compatible"


@dataclass(slots=True)
class FakeSetting:
    role: Role
    provider: Provider
    model_name: str
    base_url: str | None
    api_key: SecretStr


class FakeClient:
    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs
        self.close_calls = 0

    async def close(self) -> None:
        self.close_calls += 1


def _hybrid_settings() -> dict[Role, FakeSetting]:
    return {
        Role.ATTACKER: FakeSetting(
            role=Role.ATTACKER,
            provider=Provider.LOCAL,
            model_name="mistralai/ministral-3-14b-reasoning",
            base_url="http://127.0.0.1:1234/v1/",
            api_key=SecretStr("lm-studio"),
        ),
        Role.MUTATOR: FakeSetting(
            role=Role.MUTATOR,
            provider=Provider.LOCAL,
            model_name="mistralai/ministral-3-14b-reasoning",
            base_url="http://localhost:1234/v1",
            api_key=SecretStr("lm-studio"),
        ),
        Role.JUDGE: FakeSetting(
            role=Role.JUDGE,
            provider=Provider.HOSTED,
            model_name="gpt-4o-mini",
            base_url=None,
            api_key=SecretStr("hosted-test-key"),
        ),
    }


def test_create_role_llm_clients_builds_independent_hybrid_clients() -> None:
    created_clients: list[FakeClient] = []

    def client_factory(**kwargs: object) -> FakeClient:
        client = FakeClient(**kwargs)
        created_clients.append(client)
        return client

    clients = asyncio.run(
        create_role_llm_clients(
            _hybrid_settings(),
            options=LLMClientFactoryOptions(
                hosted_timeout_seconds=45,
                local_timeout_seconds=150,
                max_retries=1,
            ),
            client_factory=client_factory,
        )
    )

    attacker = clients.for_role("attacker")
    mutator = clients.for_role("mutator")
    judge = clients.for_role("judge")

    assert len(created_clients) == 3
    assert len({id(attacker.client), id(mutator.client), id(judge.client)}) == 3
    assert attacker.model_name == "mistralai/ministral-3-14b-reasoning"
    assert attacker.client.kwargs == {
        "api_key": "lm-studio",
        "base_url": "http://127.0.0.1:1234/v1",
        "timeout": 150,
        "max_retries": 1,
    }
    assert mutator.client.kwargs["base_url"] == "http://localhost:1234/v1"
    assert judge.model_name == "gpt-4o-mini"
    assert judge.client.kwargs == {
        "api_key": "hosted-test-key",
        "base_url": HOSTED_OPENAI_BASE_URL,
        "timeout": 45,
        "max_retries": 1,
    }

    asyncio.run(clients.close())
    assert [client.close_calls for client in created_clients] == [1, 1, 1]


@pytest.mark.parametrize(
    "local_roles",
    [
        (),
        (Role.ATTACKER,),
        (Role.MUTATOR,),
        (Role.JUDGE,),
        (Role.ATTACKER, Role.MUTATOR),
        (Role.ATTACKER, Role.JUDGE),
        (Role.MUTATOR, Role.JUDGE),
        (Role.ATTACKER, Role.MUTATOR, Role.JUDGE),
    ],
)
def test_all_eight_local_and_hosted_role_combinations(
    local_roles: tuple[Role, ...],
) -> None:
    async def run_test() -> None:
        settings = _hybrid_settings()
        local_role_set = set(local_roles)

        for role, setting in settings.items():
            if role in local_role_set:
                setting.provider = Provider.LOCAL
                setting.base_url = "http://127.0.0.1:1234/v1"
                setting.api_key = SecretStr("")
            else:
                setting.provider = Provider.HOSTED
                setting.base_url = HOSTED_OPENAI_BASE_URL
                setting.api_key = SecretStr("hosted-test-key")

        clients = await create_role_llm_clients(settings, client_factory=FakeClient)
        try:
            for role in Role:
                expected_provider = (
                    Provider.LOCAL.value if role in local_role_set else Provider.HOSTED.value
                )
                assert clients.for_role(role.value).provider == expected_provider
        finally:
            await clients.close()

    asyncio.run(run_test())


@pytest.mark.parametrize(
    "unsafe_url",
    [
        "https://evil.example/v1",
        "http://192.168.1.15:1234/v1",
        "http://user:password@localhost:1234/v1",
        "http://localhost:1234/v1?token=secret",
    ],
)
def test_local_provider_rejects_non_loopback_or_credential_bearing_urls(unsafe_url: str) -> None:
    settings = _hybrid_settings()
    settings[Role.ATTACKER].base_url = unsafe_url

    with pytest.raises(LLMClientConfigurationError):
        asyncio.run(create_role_llm_clients(settings, client_factory=FakeClient))


def test_hosted_provider_rejects_base_url_override() -> None:
    settings = _hybrid_settings()
    settings[Role.JUDGE].base_url = "https://proxy.example/v1"

    with pytest.raises(LLMClientConfigurationError, match="cannot override"):
        asyncio.run(create_role_llm_clients(settings, client_factory=FakeClient))


def test_hosted_provider_accepts_only_the_canonical_openai_base_url() -> None:
    settings = _hybrid_settings()
    settings[Role.JUDGE].base_url = "https://api.openai.com/v1"

    clients = asyncio.run(create_role_llm_clients(settings, client_factory=FakeClient))

    assert clients.for_role("judge").client.kwargs["base_url"] == HOSTED_OPENAI_BASE_URL


def test_local_provider_normalizes_full_chat_completions_route() -> None:
    settings = _hybrid_settings()
    settings[Role.ATTACKER].base_url = "http://127.0.0.1:1234/v1/chat/completions"

    clients = asyncio.run(create_role_llm_clients(settings, client_factory=FakeClient))

    assert clients.for_role("attacker").client.kwargs["base_url"] == "http://127.0.0.1:1234/v1"


def test_missing_role_is_rejected_before_any_client_is_created() -> None:
    settings = _hybrid_settings()
    del settings[Role.MUTATOR]

    with pytest.raises(LLMClientConfigurationError, match="mutator"):
        asyncio.run(create_role_llm_clients(settings, client_factory=FakeClient))


def test_local_provider_supplies_nonsecret_placeholder_when_auth_is_disabled() -> None:
    settings = _hybrid_settings()
    settings[Role.ATTACKER].api_key = SecretStr("")

    clients = asyncio.run(create_role_llm_clients(settings, client_factory=FakeClient))

    assert clients.for_role("attacker").client.kwargs["api_key"] == "lm-studio-local"


def test_factory_closes_already_created_clients_when_later_construction_fails() -> None:
    created_clients: list[FakeClient] = []

    def failing_factory(**kwargs: object) -> FakeClient:
        if created_clients:
            raise RuntimeError("construction failed")
        client = FakeClient(**kwargs)
        created_clients.append(client)
        return client

    with pytest.raises(RuntimeError, match="construction failed"):
        asyncio.run(
            create_role_llm_clients(
                _hybrid_settings(),
                client_factory=failing_factory,
            )
        )

    assert len(created_clients) == 1
    assert created_clients[0].close_calls == 1


def test_default_runtime_transport_disables_redirects_and_environment_proxies(
    monkeypatch,
) -> None:
    transport_options: list[dict[str, object]] = []

    class FakeTransport:
        def __init__(self, **kwargs: object) -> None:
            transport_options.append(kwargs)
            self.close_calls = 0

        async def aclose(self) -> None:
            self.close_calls += 1

    class CapturingOpenAI(FakeClient):
        async def close(self) -> None:
            await self.kwargs["http_client"].aclose()
            await super().close()

    monkeypatch.setattr(
        client_factory_module,
        "DefaultAsyncHttpxClient",
        FakeTransport,
    )
    monkeypatch.setattr(client_factory_module, "AsyncOpenAI", CapturingOpenAI)

    async def run_test() -> None:
        clients = await create_role_llm_clients(_hybrid_settings())
        await clients.close()

    asyncio.run(run_test())

    assert len(transport_options) == 3
    assert [options["timeout"] for options in transport_options] == [180.0, 180.0, 60.0]
    assert all(options["follow_redirects"] is False for options in transport_options)
    assert all(options["trust_env"] is False for options in transport_options)
