import asyncio
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy.sql.dml import Insert

from models.enums import TargetSystemType
from models.target_system import TargetSystem
from routes.target_systems import _serialize_target_system
from services.starter_targets import (
    STARTER_TARGETS, OPENAI_ENDPOINT, ensure_starter_targets,
    shared_target_key, starter_target_id, target_credential_source,
)


class Result:
    def __init__(self, items): self.items = items
    def scalars(self): return self
    def all(self): return self.items


class MemorySession:
    def __init__(self):
        self.targets = {}
        self.commits = 0

    async def execute(self, statement):
        params = statement.compile().params
        if isinstance(statement, Insert):
            index = 0
            while f"id_m{index}" in params:
                values = {name.removesuffix(f"_m{index}"): value for name, value in params.items() if name.endswith(f"_m{index}")}
                assert values["api_key_encrypted"] == ""
                if values["id"] in self.targets:
                    for field in ("name", "description", "role", "system_prompt"):
                        self.targets[values["id"]][field] = values[field]
                else:
                    self.targets[values["id"]] = values
                index += 1
            return Result([])
        return Result([identifier for identifier, row in self.targets.items()
                       if row["user_id"] == params["user_id_1"] and identifier in params["id_1"]])

    async def commit(self): self.commits += 1


def target_for(user_id):
    spec = STARTER_TARGETS[0]
    return TargetSystem(
        id=starter_target_id(user_id, spec.model), user_id=user_id,
        name=spec.name, description=spec.description, model_name=spec.model,
        role=spec.role, system_prompt=spec.system_prompt,
        api_endpoint=OPENAI_ENDPOINT, target_type=TargetSystemType.OPENAI_COMPATIBLE,
        api_key_encrypted="", is_active=True, created_at=datetime.now(timezone.utc),
    )


def test_starters_are_real_isolated_idempotent_and_store_no_shared_key():
    async def exercise():
        session = MemorySession()
        first, second = uuid4(), uuid4()
        await ensure_starter_targets(session, first)
        await ensure_starter_targets(session, first)
        assert len(session.targets) == 3
        assert session.commits == 2
        await ensure_starter_targets(session, second)
        assert len(session.targets) == 6
        assert {row["model_name"] for row in session.targets.values()} == {
            "gpt-4.1-mini", "gpt-4.1-nano", "gpt-4o-mini"
        }
        assert all(row["api_endpoint"] == OPENAI_ENDPOINT for row in session.targets.values())
        assert {row["role"] for row in session.targets.values()} == {"IT Support", "Restaurant Help", "Customer Support"}
        assert all(row["system_prompt"].startswith("You are") for row in session.targets.values())
        assert len({spec.system_prompt for spec in STARTER_TARGETS}) == 3
    asyncio.run(exercise())


def test_starter_key_is_server_only_and_never_serialized(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-server-key")
    target = target_for(uuid4())
    assert shared_target_key(target) == "test-server-key"
    response = _serialize_target_system(target)
    assert response.api_key_configured and response.is_starter
    assert response.credential_source == "app"
    assert "test-server-key" not in response.model_dump_json()
    assert target.api_key_encrypted == ""


def test_shared_key_cannot_be_redirected_to_custom_targets(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-server-key")
    target = target_for(uuid4())
    target.api_endpoint = "https://untrusted.test/v1"
    assert shared_target_key(target) is None
    assert target_credential_source(target) == "none"
    target.api_endpoint = OPENAI_ENDPOINT
    target.id = uuid4()
    assert shared_target_key(target) is None


def test_starters_without_app_key_report_connection_required(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    target = target_for(uuid4())
    assert _serialize_target_system(target).api_key_configured is False


def test_existing_starter_is_upgraded_without_changing_credentials_or_history_id():
    async def exercise():
        session = MemorySession()
        user_id = uuid4()
        identifier = starter_target_id(user_id, STARTER_TARGETS[0].model)
        session.targets[identifier] = {
            "id": identifier, "user_id": user_id, "name": "OpenAI GPT-4.1 Mini",
            "api_key_encrypted": "personal-encrypted-key", "is_active": False,
        }
        await ensure_starter_targets(session, user_id)
        row = session.targets[identifier]
        assert row["name"] == "IT Support" and row["system_prompt"] == STARTER_TARGETS[0].system_prompt
        assert row["api_key_encrypted"] == "personal-encrypted-key" and row["is_active"] is False
        assert row["id"] == identifier
    asyncio.run(exercise())
