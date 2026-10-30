"""Real provider targets, isolated per user, with a server-only shared credential."""
from __future__ import annotations

import os
from dataclasses import dataclass
from uuid import UUID, uuid5

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert

from models.enums import TargetSystemType
from models.target_system import TargetSystem

OPENAI_ENDPOINT = "https://api.openai.com/v1"


@dataclass(frozen=True)
class StarterTarget:
    model: str
    name: str
    description: str


STARTER_TARGETS = (
    StarterTarget("gpt-4.1-mini", "OpenAI GPT-4.1 Mini", "A real OpenAI-hosted model for instruction-following and prompt-injection evaluations."),
    StarterTarget("gpt-4.1-nano", "OpenAI GPT-4.1 Nano", "A fast, compact OpenAI model for getting started with live adversarial scans."),
    StarterTarget("gpt-4o-mini", "OpenAI GPT-4o Mini", "A real OpenAI-hosted general-purpose model for comparing attack and safety behavior."),
)


def starter_target_id(user_id: UUID, model: str) -> UUID:
    return uuid5(user_id, f"shadowledger:starter:{model}")


def starter_spec(target: TargetSystem) -> StarterTarget | None:
    if (
        not target.user_id
        or target.target_type != TargetSystemType.OPENAI_COMPATIBLE
        or target.api_endpoint != OPENAI_ENDPOINT
    ):
        return None
    return next((spec for spec in STARTER_TARGETS if (
        target.model_name == spec.model
        and target.id == starter_target_id(target.user_id, spec.model)
    )), None)


def shared_target_key(target: TargetSystem) -> str | None:
    if starter_spec(target) is None:
        return None
    if os.getenv("STARTER_TARGETS_ENABLED", "true").lower() == "false":
        return None
    return os.getenv("OPENAI_API_KEY", "").strip() or None


def target_credential_source(target: TargetSystem) -> str:
    if target.api_key_encrypted:
        return "personal"
    return "app" if shared_target_key(target) else "none"


async def ensure_starter_targets(session, user_id: UUID) -> None:
    if os.getenv("STARTER_TARGETS_ENABLED", "true").lower() == "false":
        return
    ids = [starter_target_id(user_id, spec.model) for spec in STARTER_TARGETS]
    existing = set((await session.execute(
        select(TargetSystem.id).where(TargetSystem.user_id == user_id, TargetSystem.id.in_(ids))
    )).scalars().all())
    missing = [spec for spec in STARTER_TARGETS if starter_target_id(user_id, spec.model) not in existing]
    if not missing:
        return
    await session.execute(insert(TargetSystem).values([
        {
            "id": starter_target_id(user_id, spec.model), "user_id": user_id,
            "name": spec.name, "description": spec.description,
            "api_endpoint": OPENAI_ENDPOINT, "target_type": TargetSystemType.OPENAI_COMPATIBLE,
            "api_key_encrypted": "", "model_name": spec.model, "is_active": True,
        }
        for spec in missing
    ]).on_conflict_do_nothing(index_elements=[TargetSystem.id]))
    await session.commit()
