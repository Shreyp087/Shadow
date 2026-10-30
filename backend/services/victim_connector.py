from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass
from time import perf_counter
from typing import Any
from urllib.parse import quote, quote_plus, urlsplit

import httpx
from anthropic import AsyncAnthropic

from app.core.config import get_settings
from models.enums import TargetSystemType
from models.target_system import TargetSystem
from utils.encryption import decrypt_value
from utils.network_security import parse_ip_literal, require_global_ip_address
from services.starter_targets import shared_target_key


@dataclass(slots=True)
class VictimResponse:
    response_text: str
    latency_ms: int
    tokens_used: int | None
    error: str | None = None


class VictimConnector:
    def __init__(
        self,
        target_system: TargetSystem,
        *,
        timeout_seconds: float = 15.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.target_system = target_system
        self.timeout_seconds = timeout_seconds
        self.timeout = httpx.Timeout(timeout_seconds)
        self.transport = transport

    async def send_prompt(self, prompt: str) -> VictimResponse:
        started_at = perf_counter()
        api_key: str | None = None

        try:
            if not self.target_system.is_active:
                raise ValueError("Target system is inactive")

            await self._validate_endpoint_destination()
            if self.target_system.api_key_encrypted:
                api_key = decrypt_value(self.target_system.api_key_encrypted)
            else:
                api_key = shared_target_key(self.target_system)
                if not api_key:
                    raise ValueError("No API credential is configured for this target")

            if self.target_system.target_type == TargetSystemType.OPENAI_COMPATIBLE:
                response_text, tokens_used = await self._send_openai_compatible(prompt, api_key)
            elif self.target_system.target_type == TargetSystemType.ANTHROPIC:
                response_text, tokens_used = await self._send_anthropic(prompt, api_key)
            else:
                raise ValueError(f"Unsupported target_type: {self.target_system.target_type}")

            return VictimResponse(
                response_text=response_text,
                latency_ms=self._latency_ms(started_at),
                tokens_used=tokens_used,
            )
        except Exception as exc:
            return VictimResponse(
                response_text="",
                latency_ms=self._latency_ms(started_at),
                tokens_used=None,
                error=self._format_error(
                    exc,
                    secrets=(api_key, self.target_system.api_key_encrypted),
                ),
            )

    async def _send_openai_compatible(self, prompt: str, api_key: str) -> tuple[str, int | None]:
        messages = []
        if self.target_system.system_prompt:
            messages.append({"role": "system", "content": self.target_system.system_prompt})
        messages.append({"role": "user", "content": prompt})
        payload = {
            "model": self.target_system.model_name,
            "messages": messages,
        }
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(
            timeout=self.timeout,
            transport=self.transport,
            trust_env=False,
        ) as client:
            response = await client.post(self._openai_chat_completions_url(), json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()

        return self._extract_openai_response_text(data), self._extract_openai_tokens(data)

    async def _send_anthropic(self, prompt: str, api_key: str) -> tuple[str, int | None]:
        base_url = self._anthropic_base_url()

        async with httpx.AsyncClient(
            timeout=self.timeout,
            transport=self.transport,
            base_url=base_url,
            trust_env=False,
        ) as http_client:
            client = AsyncAnthropic(
                api_key=api_key,
                base_url=base_url,
                timeout=self.timeout_seconds,
                http_client=http_client,
            )
            message = await client.messages.create(
                model=self.target_system.model_name,
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
                **({"system": self.target_system.system_prompt} if self.target_system.system_prompt else {}),
            )

        return self._extract_anthropic_response_text(message), self._extract_anthropic_tokens(message)

    def _openai_chat_completions_url(self) -> str:
        endpoint = self.target_system.api_endpoint.rstrip("/")

        if endpoint.endswith("/chat/completions"):
            return endpoint
        if endpoint.endswith("/v1"):
            return f"{endpoint}/chat/completions"
        return f"{endpoint}/v1/chat/completions"

    def _anthropic_base_url(self) -> str:
        endpoint = self.target_system.api_endpoint.rstrip("/")

        if endpoint.endswith("/v1/messages"):
            return endpoint.removesuffix("/v1/messages")
        return endpoint

    async def _validate_endpoint_destination(self) -> None:
        endpoint = urlsplit(self.target_system.api_endpoint)
        settings = get_settings()

        insecure_development_endpoint_allowed = (
            settings.environment.lower() == "development"
            and settings.allow_insecure_target_endpoints
        )
        if endpoint.scheme != "https" and not insecure_development_endpoint_allowed:
            raise ValueError("Target endpoint must use HTTPS")
        if endpoint.username is not None or endpoint.password is not None:
            raise ValueError("Target endpoint must not include credentials")
        if endpoint.fragment:
            raise ValueError("Target endpoint must not include a URL fragment")
        if endpoint.query:
            raise ValueError("Target endpoint must not include query parameters")
        if not endpoint.hostname:
            raise ValueError("Target endpoint must include a hostname")
        if settings.allow_private_target_endpoints:
            return

        literal_address = parse_ip_literal(endpoint.hostname)
        if literal_address is not None:
            require_global_ip_address(literal_address)
            return

        if self.transport is not None:
            return

        port = endpoint.port or (443 if endpoint.scheme == "https" else 80)
        resolved_addresses = await self._resolve_hostname(endpoint.hostname, port)
        if not resolved_addresses:
            raise ValueError("Target endpoint hostname did not resolve to an IP address")
        for address in resolved_addresses:
            require_global_ip_address(address)

    @staticmethod
    async def _resolve_hostname(hostname: str, port: int) -> set[str]:
        loop = asyncio.get_running_loop()
        address_info = await loop.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
        return {item[4][0] for item in address_info}

    @staticmethod
    def _extract_openai_response_text(data: dict[str, Any]) -> str:
        choices = data.get("choices") or []
        if not choices:
            return ""

        message = choices[0].get("message", {})
        content = message.get("content", "")

        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    text_value = item.get("text")
                    if isinstance(text_value, str):
                        parts.append(text_value)
            return "\n".join(part for part in parts if part)
        return str(content)

    @staticmethod
    def _extract_openai_tokens(data: dict[str, Any]) -> int | None:
        usage = data.get("usage") or {}
        total_tokens = usage.get("total_tokens")
        if isinstance(total_tokens, int):
            return total_tokens

        prompt_tokens = usage.get("prompt_tokens")
        completion_tokens = usage.get("completion_tokens")
        if isinstance(prompt_tokens, int) and isinstance(completion_tokens, int):
            return prompt_tokens + completion_tokens
        return None

    @staticmethod
    def _extract_anthropic_response_text(message: Any) -> str:
        parts: list[str] = []

        for block in getattr(message, "content", []):
            text_value = getattr(block, "text", None)
            if isinstance(text_value, str):
                parts.append(text_value)

        return "\n".join(parts)

    @staticmethod
    def _extract_anthropic_tokens(message: Any) -> int | None:
        usage = getattr(message, "usage", None)
        if usage is None:
            return None

        input_tokens = getattr(usage, "input_tokens", None)
        output_tokens = getattr(usage, "output_tokens", None)
        if isinstance(input_tokens, int) and isinstance(output_tokens, int):
            return input_tokens + output_tokens
        return None

    @staticmethod
    def _format_error(
        exc: Exception,
        *,
        secrets: tuple[str | None, ...] = (),
    ) -> str:
        message = str(exc).strip()
        redacted_message = message or exc.__class__.__name__

        for secret in secrets:
            if not secret:
                continue
            encoded_variants = {secret, quote(secret, safe=""), quote_plus(secret)}
            for variant in encoded_variants:
                if variant:
                    redacted_message = redacted_message.replace(variant, "[REDACTED]")

        return redacted_message

    @staticmethod
    def _latency_ms(started_at: float) -> int:
        return max(0, int((perf_counter() - started_at) * 1000))
