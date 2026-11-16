import asyncio
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from unittest.mock import AsyncMock

import cbor2
import httpx2
import pytest
from vercel.workflow._internal import world as sdk_world
from vercel.workflow._internal.worlds.vercel import VercelWorld

from app.workflow_transport import MAX_ATTEMPTS, ResilientVercelWorld, configure_workflow_transport, safe_to_retry

RUN_ID = "wrun_transport_test"
STEP_ID = "step_reorder_after_five"
ENDPOINT = f"/v3/runs/{RUN_ID}/events"


def make_world(handler):
    def client_factory(**kwargs):
        assert kwargs["timeout"].read == 30
        assert kwargs["timeout"].connect == 10
        assert kwargs["follow_redirects"] is False and kwargs["trust_env"] is False
        return httpx2.AsyncClient(transport=httpx2.MockTransport(handler), **kwargs)
    world = ResilientVercelWorld(client_factory=client_factory, retry_sleep=AsyncMock())
    world._auth_headers = AsyncMock(return_value={"Authorization": "Bearer test-only-token"})
    return world


def step_event():
    return sdk_world.StepCreatedEventData(
        step_name="step//app.workflows.scan_steps//reorder_vectors", input=b"private-input",
    ).into_event(STEP_ID)


def test_timeout_before_event_write_retries_same_step_and_succeeds(caplog):
    calls = []
    def handler(request):
        calls.append(cbor2.loads(request.content))
        if len(calls) == 1:
            raise httpx2.ReadTimeout("private-input test-only-token", request=request)
        return httpx2.Response(200, json={}, request=request)
    async def exercise():
        world = make_world(handler)
        await world.events_create(RUN_ID, step_event())
        assert len(calls) == 2 and calls[0] == calls[1]
        assert calls[0]["correlationId"] == STEP_ID
        world._retry_sleep.assert_awaited_once_with(1)
    asyncio.run(exercise())
    assert "private-input" not in caplog.text and "test-only-token" not in caplog.text


def test_lost_ack_preserves_sdk_conflict_handling_and_does_not_duplicate_step():
    stored, calls = set(), []
    def handler(request):
        body = cbor2.loads(request.content)
        calls.append(body)
        identifier = body["correlationId"]
        if identifier not in stored:
            stored.add(identifier)
            # The exact production failure: write succeeded but its response
            # timed out before the runtime could dispatch the created step.
            raise httpx2.ReadTimeout("response lost", request=request)
        return httpx2.Response(409, json={"message": "Step already exists"}, request=request)
    async def exercise():
        world = make_world(handler)
        with pytest.raises(sdk_world.EntityConflictError):
            await world.events_create(RUN_ID, step_event())
        assert stored == {STEP_ID} and len(calls) == 2
        assert calls[0] == calls[1]
    asyncio.run(exercise())


def test_persistent_timeout_is_bounded():
    calls = []
    def handler(request):
        calls.append(request)
        raise httpx2.ReadTimeout("unavailable", request=request)
    async def exercise():
        world = make_world(handler)
        with pytest.raises(httpx2.ReadTimeout):
            await world.events_create(RUN_ID, step_event())
        assert len(calls) == MAX_ATTEMPTS
        assert world._retry_sleep.await_count == MAX_ATTEMPTS - 1
    asyncio.run(exercise())


def test_step_started_is_not_retried_after_ambiguous_timeout():
    calls = []
    def handler(request):
        calls.append(request)
        raise httpx2.ReadTimeout("ambiguous attempt-counter increment", request=request)
    async def exercise():
        world = make_world(handler)
        with pytest.raises(httpx2.ReadTimeout):
            await world.events_create(RUN_ID, sdk_world.StepStartedEvent(correlation_id=STEP_ID))
        assert len(calls) == 1
        world._retry_sleep.assert_not_awaited()
    asyncio.run(exercise())


@pytest.mark.parametrize("status", [307, 401, 403, 409])
def test_auth_redirects_and_conflicts_are_not_retried(status):
    calls = []
    def handler(request):
        calls.append(request)
        return httpx2.Response(status, json={"message": "request rejected"},
                               headers={"location": "https://untrusted.test"}, request=request)
    async def exercise():
        world = make_world(handler)
        with pytest.raises(Exception):
            await world.events_create(RUN_ID, step_event())
        assert len(calls) == 1
        world._retry_sleep.assert_not_awaited()
    asyncio.run(exercise())


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
def test_transient_http_status_retries_with_backoff(status):
    calls = []
    def handler(request):
        calls.append(request)
        return httpx2.Response(status if len(calls) == 1 else 200, json={},
                               headers={"retry-after": "2"}, request=request)
    async def exercise():
        world = make_world(handler)
        await world.events_create(RUN_ID, step_event())
        assert len(calls) == 2
        world._retry_sleep.assert_awaited_once_with(2)
    asyncio.run(exercise())


@pytest.mark.parametrize("retry_after", ["300", format_datetime(datetime.now(timezone.utc) + timedelta(minutes=5))])
def test_long_retry_after_is_returned_to_queue_without_early_retry(retry_after):
    calls = []
    def handler(request):
        calls.append(request)
        return httpx2.Response(429, json={}, headers={"retry-after": retry_after}, request=request)
    async def exercise():
        world = make_world(handler)
        with pytest.raises(sdk_world.ThrottleError):
            await world.events_create(RUN_ID, step_event())
        assert len(calls) == 1
        world._retry_sleep.assert_not_awaited()
    asyncio.run(exercise())


def test_retry_scope_excludes_non_idempotent_event_types_and_unidentified_runs():
    assert safe_to_retry("GET", "/v2/runs/wrun_test", None)
    assert safe_to_retry("POST", ENDPOINT, step_event().model_dump())
    assert not safe_to_retry("POST", "/v3/runs/null/events", step_event().model_dump())
    assert not safe_to_retry("POST", ENDPOINT, {"eventType": "step_created"})
    for event_type in ("run_created", "step_started", "step_retrying", "hook_received"):
        assert not safe_to_retry("POST", ENDPOINT, {"eventType": event_type, "correlationId": STEP_ID})


def test_transport_is_installed_once_before_queue_registry_setup(monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    original = VercelWorld(token="test-token", project_id="test-project", team_id="test-team", environment="production")
    monkeypatch.setattr(sdk_world, "the_world", original)
    configure_workflow_transport()
    configured = sdk_world.get_world()
    assert isinstance(configured, ResilientVercelWorld)
    assert configured._token == original._token
    assert configured._headers == original._headers
    configure_workflow_transport()
    assert sdk_world.get_world() is configured
