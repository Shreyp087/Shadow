from __future__ import annotations

import inspect
import ipaddress
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urlsplit, urlunsplit

from openai import AsyncOpenAI, DefaultAsyncHttpxClient

HOSTED_OPENAI_PROVIDER = "hosted_openai"
LOCAL_OPENAI_COMPATIBLE_PROVIDER = "local_openai_compatible"
HOSTED_OPENAI_BASE_URL = "https://api.openai.com/v1"
REQUIRED_LLM_ROLES = ("attacker", "mutator", "judge")


class LLMRoleSettingLike(Protocol):
    """Runtime-only shape consumed by the scan orchestrator.

    Persisted settings can use SQLAlchemy enums or plain strings. The settings
    service is responsible for decrypting ``api_key`` before passing the value
    here; this module never persists or serializes credentials.
    """

    role: Any
    provider: Any
    model_name: str
    base_url: str | None
    api_key: Any


class LLMClientConfigurationError(ValueError):
    """Raised when a role cannot be connected without unsafe assumptions."""


@dataclass(frozen=True, slots=True)
class LLMClientFactoryOptions:
    hosted_timeout_seconds: float = 60.0
    local_timeout_seconds: float = 180.0
    max_retries: int = 1

    def __post_init__(self) -> None:
        if self.hosted_timeout_seconds <= 0 or self.local_timeout_seconds <= 0:
            raise ValueError("LLM client timeouts must be greater than zero")
        if self.max_retries < 0 or self.max_retries > 5:
            raise ValueError("LLM client max_retries must be between 0 and 5")


@dataclass(frozen=True, slots=True)
class ConfiguredRoleClient:
    role: str
    provider: str
    model_name: str
    client: Any


class RoleLLMClients:
    """Owns one independent client for every internal LLM role."""

    def __init__(self, clients: Mapping[str, ConfiguredRoleClient]) -> None:
        self._clients = dict(clients)

    def for_role(self, role: str) -> ConfiguredRoleClient:
        try:
            return self._clients[role]
        except KeyError as exc:
            raise LLMClientConfigurationError(f"Missing LLM configuration for role '{role}'") from exc

    async def close(self) -> None:
        # Clients are intentionally independent, but de-duplicate defensively if
        # a custom test/client factory returns the same object more than once.
        closed_ids: set[int] = set()
        first_error: Exception | None = None
        for configured in self._clients.values():
            client = configured.client
            if id(client) in closed_ids:
                continue
            closed_ids.add(id(client))
            close = getattr(client, "close", None)
            if close is None:
                continue
            try:
                close_result = close()
                if inspect.isawaitable(close_result):
                    await close_result
            except Exception as exc:
                first_error = first_error or exc
        if first_error is not None:
            raise first_error


async def create_role_llm_clients(
    settings: Mapping[Any, LLMRoleSettingLike],
    *,
    options: LLMClientFactoryOptions | None = None,
    client_factory: Callable[..., Any] | None = None,
) -> RoleLLMClients:
    """Build three separately configured OpenAI-compatible clients.

    Mapping keys and setting roles may be strings or enum values. Hosted OpenAI
    always uses the fixed official API base, while local clients are restricted
    to loopback URLs so a stored hosted credential cannot be redirected.
    """

    normalized_settings: dict[str, LLMRoleSettingLike] = {}
    for key, setting in settings.items():
        role = _enum_value(getattr(setting, "role", key)).lower()
        if role in normalized_settings:
            raise LLMClientConfigurationError(f"Duplicate LLM configuration for role '{role}'")
        normalized_settings[role] = setting

    missing_roles = [role for role in REQUIRED_LLM_ROLES if role not in normalized_settings]
    if missing_roles:
        raise LLMClientConfigurationError(
            f"Missing LLM configuration for role(s): {', '.join(missing_roles)}"
        )

    factory_options = options or LLMClientFactoryOptions()
    resolved_client_factory = client_factory or _create_secure_openai_client
    clients: dict[str, ConfiguredRoleClient] = {}
    try:
        for role in REQUIRED_LLM_ROLES:
            setting = normalized_settings[role]
            clients[role] = _create_role_client(
                role,
                setting,
                options=factory_options,
                client_factory=resolved_client_factory,
            )
    except Exception:
        try:
            await RoleLLMClients(clients).close()
        except Exception:
            # Preserve the construction error; cleanup is best effort here.
            pass
        raise

    return RoleLLMClients(clients)


def _create_role_client(
    role: str,
    setting: LLMRoleSettingLike,
    *,
    options: LLMClientFactoryOptions,
    client_factory: Callable[..., Any],
) -> ConfiguredRoleClient:
    provider = _enum_value(setting.provider).lower()
    model_name = str(setting.model_name).strip()
    if not model_name:
        raise LLMClientConfigurationError(f"Model name is required for role '{role}'")

    raw_api_key = _secret_value(getattr(setting, "api_key", None))

    if provider == HOSTED_OPENAI_PROVIDER:
        if not raw_api_key:
            raise LLMClientConfigurationError(f"Hosted OpenAI API key is required for role '{role}'")
        configured_base_url = str(getattr(setting, "base_url", None) or "").rstrip("/")
        if configured_base_url and configured_base_url != HOSTED_OPENAI_BASE_URL:
            raise LLMClientConfigurationError(
                f"Hosted OpenAI role '{role}' cannot override the official API base URL"
            )
        api_key = raw_api_key
        base_url = HOSTED_OPENAI_BASE_URL
        timeout = options.hosted_timeout_seconds
    elif provider == LOCAL_OPENAI_COMPATIBLE_PROVIDER:
        base_url = _normalize_loopback_base_url(getattr(setting, "base_url", None), role)
        # AsyncOpenAI requires a non-empty key even when LM Studio authentication
        # is disabled. This non-secret placeholder never leaves the loopback host.
        api_key = raw_api_key or "lm-studio-local"
        timeout = options.local_timeout_seconds
    else:
        raise LLMClientConfigurationError(
            f"Unsupported LLM provider '{provider}' for role '{role}'"
        )

    client = client_factory(
        api_key=api_key,
        base_url=base_url,
        timeout=timeout,
        max_retries=options.max_retries,
    )
    return ConfiguredRoleClient(
        role=role,
        provider=provider,
        model_name=model_name,
        client=client,
    )


def _create_secure_openai_client(**kwargs: Any) -> AsyncOpenAI:
    """Create an SDK client without ambient proxies or credential-bearing redirects."""
    timeout = kwargs.get("timeout")
    http_client = DefaultAsyncHttpxClient(
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
    )
    return AsyncOpenAI(**kwargs, http_client=http_client)


def _normalize_loopback_base_url(base_url: str | None, role: str) -> str:
    raw_url = str(base_url or "").strip()
    if not raw_url:
        raise LLMClientConfigurationError(f"Local base URL is required for role '{role}'")

    parsed = urlsplit(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise LLMClientConfigurationError(
            f"Local base URL for role '{role}' must be an HTTP(S) loopback URL"
        )
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise LLMClientConfigurationError(
            f"Local base URL for role '{role}' cannot contain credentials, query parameters, or fragments"
        )

    hostname = parsed.hostname.rstrip(".").lower()
    if hostname != "localhost":
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError as exc:
            raise LLMClientConfigurationError(
                f"Local base URL for role '{role}' must use localhost or a loopback IP address"
            ) from exc
        if not address.is_loopback:
            raise LLMClientConfigurationError(
                f"Local base URL for role '{role}' must use localhost or a loopback IP address"
            )

    normalized_path = parsed.path.rstrip("/")
    if normalized_path.endswith("/chat/completions"):
        normalized_path = normalized_path[: -len("/chat/completions")].rstrip("/")
    normalized_path = normalized_path or "/v1"
    return urlunsplit((parsed.scheme, parsed.netloc, normalized_path, "", ""))


def _enum_value(value: Any) -> str:
    return str(getattr(value, "value", value)).strip()


def _secret_value(value: Any) -> str | None:
    if value is None:
        return None
    get_secret_value = getattr(value, "get_secret_value", None)
    raw_value = get_secret_value() if callable(get_secret_value) else value
    normalized = str(raw_value).strip()
    return normalized or None
