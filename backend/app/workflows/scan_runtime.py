from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import UUID, uuid5

from sqlalchemy import select, text
from vercel.workflow import FatalError

from models.base import AsyncSessionLocal
from models.attack_result import AttackResult
from models.attack_run import AttackRun
from models.attack_vector import AttackVector
from models.enums import AttackRunStatus
from models.target_system import TargetSystem
from services.attacker_agent import AttackerAgent
from services.llm_client_factory import LLMClientFactoryOptions, create_role_llm_clients
from services.llm_role_settings import load_effective_llm_role_settings
from services.mutation_engine import MutationEngine
from services.risk_scorer import RiskScorer
from services.trust_ledger import TrustLedger
from services.victim_connector import VictimConnector

STEP_TIMEOUT_SECONDS = 210


class SerializedTrustLedger(TrustLedger):
    async def append(self, attack_result_id: UUID, payload: dict):
        # The chain spans all runs. Hold this lock only from append until commit.
        await self.db_session.execute(text("SELECT pg_advisory_xact_lock(763928451)"))
        return await super().append(attack_result_id, payload)


async def locked_run(session, run_id: str) -> AttackRun:
    run = await session.scalar(
        select(AttackRun).where(AttackRun.id == UUID(run_id)).with_for_update()
    )
    if run is None:
        raise FatalError("Scan record no longer exists")
    return run


@asynccontextmanager
async def configured_agent(session, run: AttackRun):
    target = await session.get(TargetSystem, run.target_system_id)
    if target is None or not target.is_active or target.user_id != run.user_id:
        raise FatalError("Scan target is unavailable")
    clients = None
    try:
        settings = await load_effective_llm_role_settings(session, run.user_id)
        clients = await create_role_llm_clients(
            settings,
            options=LLMClientFactoryOptions(hosted_timeout_seconds=45, max_retries=0),
        )
        attacker = clients.for_role("attacker")
        mutator = clients.for_role("mutator")
        judge = clients.for_role("judge")
        yield AttackerAgent(
            db_session=session,
            llm_client=attacker.client,
            victim_connector=VictimConnector(target),
            scorer_service=RiskScorer(judge.client, model_name=judge.model_name,
                                      target_role=target.role, target_system_prompt=target.system_prompt),
            trust_ledger=SerializedTrustLedger(session),
            mutation_engine=MutationEngine(mutator.client, model_name=mutator.model_name),
            model_name=attacker.model_name,
        )
    except FatalError:
        raise
    except Exception as exc:
        # Provider response bodies and credentials must not enter workflow errors.
        raise RuntimeError(f"Scan operation failed ({type(exc).__name__})") from None
    finally:
        if clients is not None:
            try:
                await clients.close()
            except Exception:
                pass


async def recent_results(session, run_id: str) -> list[AttackResult]:
    result = await session.scalars(
        select(AttackResult)
        .where(AttackResult.attack_run_id == UUID(run_id))
        .order_by(AttackResult.executed_at.asc(), AttackResult.id.asc())
    )
    return list(result.all())


async def begin_scan(run_id: str) -> bool:
    async with AsyncSessionLocal() as session:
        run = await locked_run(session, run_id)
        if run.status in (AttackRunStatus.COMPLETED, AttackRunStatus.FAILED):
            return False
        if run.status == AttackRunStatus.PENDING:
            run.status = AttackRunStatus.RUNNING
            run.started_at = datetime.now(timezone.utc)
            await session.commit()
        return True


async def execute_attempt(
    run_id: str, vector_id: str, attempt: str, prompt: str | None = None
) -> bool:
    result_id = uuid5(UUID(run_id), f"{vector_id}:{attempt}")
    async with AsyncSessionLocal() as session:
        run = await locked_run(session, run_id)
        existing = await session.get(AttackResult, result_id)
        if existing is not None:
            return AttackerAgent._should_mutate(existing)
        if run.status != AttackRunStatus.RUNNING:
            raise FatalError("Scan is no longer running")
        vector = await session.get(AttackVector, UUID(vector_id))
        if vector is None or not vector.is_active:
            raise FatalError("Scan vector is unavailable")
        async with configured_agent(session, run) as agent:
            result = await asyncio.wait_for(
                agent.run_attack_vector(
                    run.id,
                    vector,
                    result_id=result_id,
                    prompt_override=prompt,
                    is_mutation=attempt != "base",
                ),
                timeout=STEP_TIMEOUT_SECONDS,
            )
            await session.commit()
            return agent._should_mutate(result)


async def mutation_prompts(run_id: str, vector_id: str) -> list[str]:
    async with AsyncSessionLocal() as session:
        run = await locked_run(session, run_id)
        vector = await session.get(AttackVector, UUID(vector_id))
        if vector is None:
            raise FatalError("Scan vector is unavailable")
        results = await recent_results(session, run_id)
        async with configured_agent(session, run) as agent:
            return await asyncio.wait_for(
                agent._generate_mutation_prompts(vector, results),
                timeout=STEP_TIMEOUT_SECONDS,
            )


async def reorder_vectors(run_id: str, remaining: list[str], all_vectors: list[str]) -> list[str]:
    async with AsyncSessionLocal() as session:
        results = await recent_results(session, run_id)
        vectors = [await session.get(AttackVector, UUID(item)) for item in all_vectors]
        available = [vector for vector in vectors if vector is not None and vector.is_active]
        # Ordering is based on persisted scores, so no provider credentials are needed.
        ordered = await MutationEngine(None).select_next_vectors(available, results)
        requested = set(remaining)
        return [str(vector.id) for vector in ordered if str(vector.id) in requested]


async def finish_scan(run_id: str, *, succeeded: bool) -> None:
    async with AsyncSessionLocal() as session:
        run = await locked_run(session, run_id)
        if run.status in (AttackRunStatus.COMPLETED, AttackRunStatus.FAILED):
            return
        run.status = AttackRunStatus.COMPLETED if succeeded else AttackRunStatus.FAILED
        run.failure_reason = None if succeeded else "The scan worker stopped before completion. Start a new scan to retry."
        run.completed_at = datetime.now(timezone.utc)
        await session.commit()
