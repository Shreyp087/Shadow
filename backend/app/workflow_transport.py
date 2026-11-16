"""Narrow transport compatibility layer for pinned vercel-workflow 0.12.0.

Its event HTTP client defaults to a five-second read timeout with no retry.
An acknowledged-late step_created write can otherwise strand a created step
before its queue send. Keep SDK auth, schemas and conflict handling intact.
Only reads and idempotent step creation are retried; step_started increments
an attempt counter and must never be blindly replayed after an ambiguous read.
This module is imported on the host only, never in the workflow sandbox.
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

import cbor2
import httpx2
from vercel.workflow._internal import world as sdk_world
from vercel.workflow._internal.worlds.vercel import VercelWorld, _parse_response_body

logger = logging.getLogger(__name__)
MAX_ATTEMPTS = 3
REQUEST_TIMEOUT = httpx2.Timeout(connect=10, read=30, write=10, pool=10)
RETRY_STATUS = frozenset({429, 500, 502, 503, 504})


def safe_to_retry(method: str, endpoint: str, data: Any) -> bool:
    if method.upper() in {"GET", "HEAD"}:
        return True
    parts = endpoint.split("?", 1)[0].split("/")
    return (
        method.upper() == "POST"
        and len(parts) == 5 and parts[:3] == ["", "v3", "runs"]
        and parts[3].startswith("wrun_") and parts[4] == "events"
        and isinstance(data, dict) and data.get("eventType") == "step_created"
        and bool(data.get("correlationId"))
    )


class ResilientVercelWorld(VercelWorld):
    def __init__(self, *, client_factory=None, retry_sleep=None, **kwargs):
        super().__init__(**kwargs)
        self._request_client = client_factory or httpx2.AsyncClient
        self._retry_sleep = retry_sleep or asyncio.sleep

    async def _cbor_request(self, method: str, endpoint: str, *, schema, data: Any = None):
        body = cbor2.dumps(data) if data is not None else None
        retryable = safe_to_retry(method, endpoint, data)
        attempts = MAX_ATTEMPTS if retryable else 1
        for attempt in range(attempts):
            headers = await self._auth_headers()
            headers.update({"Accept": "application/cbor", "X-Request-Time": datetime.now(timezone.utc).isoformat()})
            if body is not None:
                headers["Content-Type"] = "application/cbor"
            try:
                async with self._request_client(
                    base_url=self._base_url, headers=headers, timeout=REQUEST_TIMEOUT,
                    follow_redirects=False, trust_env=False,
                ) as client:
                    response = await client.request(method, endpoint, content=body)
            except httpx2.TransportError as exc:
                if attempt + 1 == attempts:
                    raise
                # No body, endpoint, authentication header, or provider secret
                # enters a retry log. Resend exactly the same correlation ID.
                logger.warning("Workflow request retry (error_type=%s, attempt=%d)", type(exc).__name__, attempt + 1)
                await self._retry_sleep(2 ** attempt)
                continue

            if response.is_success:
                return schema.from_wire(_parse_response_body(response))
            if response.status_code in RETRY_STATUS and attempt + 1 < attempts:
                delay = float(2 ** attempt)
                retry_after = response.headers.get("retry-after", "0")
                try:
                    delay = max(delay, float(retry_after))
                except ValueError:
                    try:
                        when = parsedate_to_datetime(retry_after)
                        delay = max(delay, (when - datetime.now(timezone.utc)).total_seconds())
                    except (TypeError, ValueError, OverflowError):
                        pass
                # Leave long throttles to queue redelivery instead of exceeding
                # the function budget or retrying before the service permits it.
                if delay <= 30:
                    logger.warning("Workflow request retry (http_status=%d, attempt=%d)", response.status_code, attempt + 1)
                    await self._retry_sleep(delay)
                    continue
            # In particular, preserve 409. The SDK already handles a duplicate
            # step_created by dispatching the original step with its existing ID.
            raise self._error_for_response(method, endpoint, response)


def configure_workflow_transport() -> None:
    if os.getenv("VERCEL") != "1":
        return
    current = sdk_world.get_world()
    if not isinstance(current, VercelWorld) or isinstance(current, ResilientVercelWorld):
        return
    sdk_world.set_world(ResilientVercelWorld(
        token=current._token,
        environment=current._headers.get("x-vercel-environment"),
        project_id=current._project_id,
        team_id=current._team_id,
    ))
