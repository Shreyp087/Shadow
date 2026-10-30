from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from math import ceil
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.clerk import verify_clerk_token
from models.attack_result import AttackResult
from models.attack_run import AttackRun
from models.attack_vector import AttackVector
from models.enums import AttackRunStatus, AttackVectorCategory, RiskCategory
from models.target_system import TargetSystem
from models.trust_ledger_entry import TrustLedgerEntry
from models.user import User
from schemas.attack_result import AttackResultResponse
from schemas.attack_run import AttackRunResponse, AttackRunsSummaryResponse, CreateAttackRunRequest
from schemas.common import APIResponse
from routes._user_context import resolve_request_user
from services.attacker_agent import AttackerAgent
from services.llm_client_factory import RoleLLMClients, create_role_llm_clients
from services.llm_role_settings import (
    LLMSettingsConfigurationError,
    load_effective_llm_role_settings,
)
from services.mutation_engine import MutationEngine
from services.report_generator import ReportGenerator
from services.risk_scorer import RiskScorer
from services.trust_ledger import TrustLedger
from services.victim_connector import VictimConnector
from services.starter_targets import target_credential_source

from app.db.session import get_db_session
from models.base import AsyncSessionLocal

router = APIRouter(prefix="/api/v1/attack-runs", tags=["attack-runs"])
logger = logging.getLogger(__name__)


DbSession = Annotated[AsyncSession, Depends(get_db_session)]
ClerkUserId = Annotated[str, Depends(verify_clerk_token)]


async def get_read_only_user(
    db_session: DbSession,
    clerk_user_id: ClerkUserId,
) -> User:
    return await _get_authenticated_user(db_session, clerk_user_id)


ReadOnlyUser = Annotated[User, Depends(get_read_only_user)]


@router.get("/", response_model=APIResponse[list[AttackRunResponse]])
async def list_attack_runs(
    db_session: DbSession,
    user: ReadOnlyUser,
) -> APIResponse[list[AttackRunResponse]]:
    statement = (
        select(AttackRun)
        .where(AttackRun.user_id == user.id)
        .order_by(AttackRun.started_at.desc().nullslast(), AttackRun.id.desc())
    )
    result = await db_session.execute(statement)
    items = [AttackRunResponse.model_validate(run) for run in result.scalars().all()]

    return APIResponse(
        data=items,
        meta={"count": len(items)},
    )


@router.get("/summary", response_model=APIResponse[AttackRunsSummaryResponse])
async def get_attack_runs_summary(
    db_session: DbSession,
    user: ReadOnlyUser,
) -> APIResponse[AttackRunsSummaryResponse]:
    totals_statement = select(
        func.count(AttackRun.id).label("total_scans"),
        func.coalesce(func.sum(AttackRun.vulnerabilities_found), 0).label("vulnerabilities_found"),
        func.avg(AttackRun.risk_score_avg).label("avg_risk_score"),
    ).where(AttackRun.user_id == user.id)
    totals = (await db_session.execute(totals_statement)).one()

    critical_findings_statement = (
        select(func.count(AttackResult.id))
        .join(AttackRun, AttackResult.attack_run_id == AttackRun.id)
        .where(
            AttackRun.user_id == user.id,
            AttackResult.risk_category == RiskCategory.CRITICAL,
        )
    )
    critical_findings = int((await db_session.scalar(critical_findings_statement)) or 0)
    total_results_statement = (
        select(func.count(AttackResult.id))
        .join(AttackRun, AttackResult.attack_run_id == AttackRun.id)
        .where(AttackRun.user_id == user.id)
    )
    total_results = int((await db_session.scalar(total_results_statement)) or 0)

    summary = AttackRunsSummaryResponse(
        total_scans=int(totals.total_scans or 0),
        vulnerabilities_found=int(totals.vulnerabilities_found or 0),
        critical_findings=critical_findings,
        avg_risk_score=totals.avg_risk_score,
    )

    return APIResponse(
        data=summary,
        meta={"source": "attack_runs", "total_results": total_results},
    )


@router.post("/", response_model=APIResponse[AttackRunResponse], status_code=status.HTTP_201_CREATED)
async def create_attack_run(
    payload: CreateAttackRunRequest,
    background_tasks: BackgroundTasks,
    db_session: DbSession,
    clerk_user_id: ClerkUserId,
) -> APIResponse[AttackRunResponse]:
    user = await _get_authenticated_user(db_session, clerk_user_id)
    target_system = await _get_user_target_system(db_session, user, payload.target_system_id)
    if target_credential_source(target_system) == "none":
        raise HTTPException(status_code=409, detail="A provider credential is required for this target")
    vector_ids = await _resolve_vector_ids(db_session, payload.vector_category_filter)

    if not vector_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active attack vectors matched the requested filters",
        )

    try:
        await load_effective_llm_role_settings(db_session, user.id)
    except LLMSettingsConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    attack_run = AttackRun(
        target_system_id=target_system.id,
        user_id=user.id,
        status=AttackRunStatus.PENDING,
        total_attacks=0,
        vulnerabilities_found=0,
        risk_score_avg=None,
    )
    db_session.add(attack_run)
    await db_session.commit()
    await db_session.refresh(attack_run)

    workflow_run_id = None
    if os.getenv("VERCEL") == "1":
        try:
            from vercel import workflow
            from app.workflows import attack_scan

            handle = await workflow.start(
                attack_scan, str(attack_run.id), [str(item) for item in vector_ids]
            )
            workflow_run_id = handle.run_id
        except Exception:
            attack_run.status = AttackRunStatus.FAILED
            attack_run.completed_at = datetime.now(timezone.utc)
            await db_session.commit()
            raise HTTPException(status_code=503, detail="Scan could not be queued") from None
    else:
        background_tasks.add_task(
            _execute_attack_run_background,
            attack_run.id,
            target_system.id,
            vector_ids,
        )

    return APIResponse(
        data=AttackRunResponse.model_validate(attack_run),
        meta={
            "vector_count": len(vector_ids),
            "status": attack_run.status.value,
            **({"workflow_run_id": workflow_run_id} if workflow_run_id else {}),
        },
    )


@router.get("/{run_id}", response_model=APIResponse[AttackRunResponse])
async def get_attack_run(
    run_id: UUID,
    db_session: DbSession,
    clerk_user_id: ClerkUserId,
) -> APIResponse[AttackRunResponse]:
    user = await _get_authenticated_user(db_session, clerk_user_id)
    attack_run = await _get_user_attack_run(db_session, user, run_id)
    summary = await _build_attack_run_summary(db_session, attack_run.id)

    return APIResponse(
        data=AttackRunResponse.model_validate(attack_run),
        meta=summary,
    )


@router.get("/{run_id}/results", response_model=APIResponse[list[AttackResultResponse]])
async def list_attack_run_results(
    run_id: UUID,
    db_session: DbSession,
    clerk_user_id: ClerkUserId,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> APIResponse[list[AttackResultResponse]]:
    user = await _get_authenticated_user(db_session, clerk_user_id)
    attack_run = await _get_user_attack_run(db_session, user, run_id)

    total_results = await _count_attack_results(db_session, attack_run.id)
    statement = (
        select(AttackResult, AttackVector.category, TrustLedgerEntry.entry_hash)
        .join(AttackVector, AttackResult.attack_vector_id == AttackVector.id)
        .outerjoin(TrustLedgerEntry, TrustLedgerEntry.attack_result_id == AttackResult.id)
        .where(AttackResult.attack_run_id == attack_run.id)
        .order_by(AttackResult.executed_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    result = await db_session.execute(statement)
    items = [
        _serialize_attack_result_row(attack_result, attack_category, entry_hash)
        for attack_result, attack_category, entry_hash in result.all()
    ]

    return APIResponse(
        data=items,
        meta={
            "page": page,
            "page_size": page_size,
            "total": total_results,
            "total_pages": ceil(total_results / page_size) if total_results else 0,
        },
    )


@router.get("/{run_id}/results/critical", response_model=APIResponse[list[AttackResultResponse]])
async def list_critical_attack_results(
    run_id: UUID,
    db_session: DbSession,
    clerk_user_id: ClerkUserId,
) -> APIResponse[list[AttackResultResponse]]:
    user = await _get_authenticated_user(db_session, clerk_user_id)
    attack_run = await _get_user_attack_run(db_session, user, run_id)

    statement = (
        select(AttackResult, AttackVector.category, TrustLedgerEntry.entry_hash)
        .join(AttackVector, AttackResult.attack_vector_id == AttackVector.id)
        .outerjoin(TrustLedgerEntry, TrustLedgerEntry.attack_result_id == AttackResult.id)
        .where(
            AttackResult.attack_run_id == attack_run.id,
            AttackResult.risk_category.in_([RiskCategory.CRITICAL, RiskCategory.HIGH]),
        )
        .order_by(AttackResult.executed_at.desc())
    )
    result = await db_session.execute(statement)
    items = [
        _serialize_attack_result_row(attack_result, attack_category, entry_hash)
        for attack_result, attack_category, entry_hash in result.all()
    ]

    return APIResponse(
        data=items,
        meta={"count": len(items), "categories": [RiskCategory.HIGH.value, RiskCategory.CRITICAL.value]},
    )


@router.get("/{run_id}/report", response_class=Response)
async def download_attack_run_report(
    run_id: UUID,
    db_session: DbSession,
    clerk_user_id: ClerkUserId,
) -> Response:
    user = await _get_authenticated_user(db_session, clerk_user_id)
    attack_run = await _get_user_attack_run(db_session, user, run_id)

    report_generator = ReportGenerator()
    report_bytes = await report_generator.generate_audit_report(attack_run.id, db_session)

    return Response(
        content=report_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="shadowledger-attack-run-{attack_run.id}.pdf"',
        },
    )


async def _execute_attack_run_background(
    attack_run_id: UUID,
    target_system_id: UUID,
    vector_ids: list[UUID],
) -> None:
    role_clients: RoleLLMClients | None = None

    try:
        async with AsyncSessionLocal() as db_session:
            attack_run = await db_session.get(AttackRun, attack_run_id)
            target_system = await db_session.get(TargetSystem, target_system_id)

            if attack_run is None:
                return
            if target_system is None or not target_system.is_active:
                attack_run.status = AttackRunStatus.FAILED
                attack_run.completed_at = datetime.now(timezone.utc)
                await db_session.commit()
                return

            effective_settings = await load_effective_llm_role_settings(
                db_session,
                attack_run.user_id,
            )
            role_clients = await create_role_llm_clients(effective_settings)
            attacker_client = role_clients.for_role("attacker")
            mutator_client = role_clients.for_role("mutator")
            judge_client = role_clients.for_role("judge")

            attacker = AttackerAgent(
                db_session=db_session,
                llm_client=attacker_client.client,
                victim_connector=VictimConnector(target_system),
                scorer_service=RiskScorer(
                    judge_client.client,
                    model_name=judge_client.model_name,
                ),
                trust_ledger=TrustLedger(db_session),
                mutation_engine=MutationEngine(
                    mutator_client.client,
                    model_name=mutator_client.model_name,
                ),
                model_name=attacker_client.model_name,
            )
            await attacker.run_full_scan(
                attack_run.id,
                target_system,
                vector_ids,
            )
    except Exception as exc:
        logger.error(
            "Attack run background execution failed (run_id=%s, error_type=%s)",
            attack_run_id,
            exc.__class__.__name__,
        )
        async with AsyncSessionLocal() as db_session:
            attack_run = await db_session.get(AttackRun, attack_run_id)
            if attack_run is not None:
                attack_run.status = AttackRunStatus.FAILED
                attack_run.completed_at = datetime.now(timezone.utc)
                await db_session.commit()
    finally:
        if role_clients is not None:
            await role_clients.close()


async def _get_authenticated_user(db_session: AsyncSession, clerk_user_id: str) -> User:
    return await resolve_request_user(db_session, clerk_user_id)


async def _get_user_target_system(db_session: AsyncSession, user: User, target_system_id: UUID) -> TargetSystem:
    statement = select(TargetSystem).where(
        TargetSystem.id == target_system_id,
        TargetSystem.user_id == user.id,
    )
    target_system = await db_session.scalar(statement)
    if target_system is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target system was not found for the authenticated user",
        )
    if not target_system.is_active:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Target system is inactive",
        )
    return target_system


async def _get_user_attack_run(db_session: AsyncSession, user: User, run_id: UUID) -> AttackRun:
    statement = select(AttackRun).where(AttackRun.id == run_id, AttackRun.user_id == user.id)
    attack_run = await db_session.scalar(statement)
    if attack_run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Attack run was not found for the authenticated user",
        )
    return attack_run


async def _resolve_vector_ids(
    db_session: AsyncSession,
    vector_category_filter: list[str] | None,
) -> list[UUID]:
    statement = select(AttackVector.id).where(AttackVector.is_active.is_(True))
    categories = _parse_vector_categories(vector_category_filter)
    if categories:
        statement = statement.where(AttackVector.category.in_(categories))

    result = await db_session.execute(statement.order_by(AttackVector.name.asc()))
    return list(result.scalars().all())


def _parse_vector_categories(vector_category_filter: list[str] | None) -> list[AttackVectorCategory]:
    if not vector_category_filter:
        return []

    parsed_categories: list[AttackVectorCategory] = []
    invalid_values: list[str] = []

    for value in vector_category_filter:
        normalized = value.strip().upper()
        try:
            parsed_categories.append(AttackVectorCategory(normalized))
        except ValueError:
            invalid_values.append(value)

    if invalid_values:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Invalid vector categories: {', '.join(invalid_values)}",
        )

    return parsed_categories


def _serialize_attack_result_row(
    attack_result: AttackResult,
    attack_category: AttackVectorCategory,
    trust_ledger_entry_hash: str | None,
) -> AttackResultResponse:
    return AttackResultResponse(
        id=attack_result.id,
        attack_run_id=attack_result.attack_run_id,
        attack_vector_id=attack_result.attack_vector_id,
        attack_category=attack_category,
        prompt_sent=attack_result.prompt_sent,
        response_received=attack_result.response_received,
        risk_score=attack_result.risk_score,
        is_mutation=attack_result.is_mutation,
        risk_category=attack_result.risk_category,
        risk_reason=attack_result.risk_reason,
        executed_at=attack_result.executed_at,
        trust_ledger_entry_hash=trust_ledger_entry_hash,
    )


async def _count_attack_results(db_session: AsyncSession, attack_run_id: UUID) -> int:
    statement = select(func.count(AttackResult.id)).where(AttackResult.attack_run_id == attack_run_id)
    return int((await db_session.scalar(statement)) or 0)


async def _build_attack_run_summary(db_session: AsyncSession, attack_run_id: UUID) -> dict[str, object]:
    total_results = await _count_attack_results(db_session, attack_run_id)

    grouped_statement = (
        select(AttackResult.risk_category, func.count(AttackResult.id))
        .where(AttackResult.attack_run_id == attack_run_id)
        .group_by(AttackResult.risk_category)
    )
    grouped_result = await db_session.execute(grouped_statement)

    risk_breakdown = {category.value: count for category, count in grouped_result.all()}
    critical_or_high = risk_breakdown.get(RiskCategory.CRITICAL.value, 0) + risk_breakdown.get(RiskCategory.HIGH.value, 0)

    return {
        "total_results": total_results,
        "critical_or_high_results": critical_or_high,
        "risk_breakdown": risk_breakdown,
    }
