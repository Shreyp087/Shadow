from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Sequence
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import Float, case, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.clerk import verify_clerk_token
from models.attack_result import AttackResult
from models.attack_run import AttackRun
from models.attack_vector import AttackVector
from models.enums import AttackVectorCategory, RiskCategory
from models.target_system import TargetSystem
from models.user import User
from routes._user_context import resolve_request_user
from schemas.analytics import AttackSurfaceSummaryItem, AttackSurfaceTrend, TargetRiskTrendPoint
from schemas.common import APIResponse

from app.db.session import get_db_session

router = APIRouter(prefix="/api/v1/analytics", tags=["analytics"])

RISK_CATEGORY_RANKS: dict[RiskCategory, int] = {
    RiskCategory.SAFE: 0,
    RiskCategory.LOW: 1,
    RiskCategory.MEDIUM: 2,
    RiskCategory.HIGH: 3,
    RiskCategory.CRITICAL: 4,
}
RISK_RANK_TO_CATEGORY = {rank: category for category, rank in RISK_CATEGORY_RANKS.items()}
ALL_ATTACK_VECTOR_CATEGORIES = list(AttackVectorCategory)


@router.get("/target/{target_system_id}/trend", response_model=APIResponse[list[TargetRiskTrendPoint]])
async def get_target_risk_trend(
    target_system_id: UUID,
    db_session: AsyncSession = Depends(get_db_session),
    clerk_user_id: str = Depends(verify_clerk_token),
) -> APIResponse[list[TargetRiskTrendPoint]]:
    user = await _get_authenticated_user(db_session, clerk_user_id)
    target_system = await _get_user_target_system(db_session, user, target_system_id)

    today = _utc_today()
    window_start = _at_utc_start_of_day(today - timedelta(days=29))
    day_bucket = func.date(AttackResult.executed_at).label("bucket_date")

    statement = (
        select(
            day_bucket,
            cast(func.avg(AttackResult.risk_score), Float).label("avg_risk_score"),
            func.count(AttackResult.id).label("total_attacks"),
            func.sum(case((AttackResult.risk_category == RiskCategory.CRITICAL, 1), else_=0)).label("critical_count"),
            func.sum(case((AttackResult.risk_category == RiskCategory.HIGH, 1), else_=0)).label("high_count"),
            func.sum(case((AttackResult.risk_category == RiskCategory.MEDIUM, 1), else_=0)).label("medium_count"),
        )
        .join(AttackRun, AttackResult.attack_run_id == AttackRun.id)
        .where(
            AttackRun.target_system_id == target_system.id,
            AttackResult.executed_at >= window_start,
        )
        .group_by(day_bucket)
        .order_by(day_bucket.asc())
    )

    rows = (await db_session.execute(statement)).all()
    points = _build_trend_points(rows, today)

    return APIResponse(
        data=points,
        meta={
            "target_system_id": str(target_system.id),
            "window_days": 30,
        },
    )


@router.get("/target/{target_system_id}/attack-surface", response_model=APIResponse[list[AttackSurfaceSummaryItem]])
async def get_target_attack_surface(
    target_system_id: UUID,
    db_session: AsyncSession = Depends(get_db_session),
    clerk_user_id: str = Depends(verify_clerk_token),
) -> APIResponse[list[AttackSurfaceSummaryItem]]:
    user = await _get_authenticated_user(db_session, clerk_user_id)
    target_system = await _get_user_target_system(db_session, user, target_system_id)

    worst_risk_rank = func.max(
        case(
            *[(AttackResult.risk_category == category, rank) for category, rank in RISK_CATEGORY_RANKS.items()],
            else_=0,
        )
    ).label("worst_risk_rank")

    summary_statement = (
        select(
            AttackVector.category.label("category"),
            worst_risk_rank,
            func.count(AttackResult.id).label("total_attacks"),
            func.sum(
                case(
                    (AttackResult.risk_category.in_([RiskCategory.HIGH, RiskCategory.CRITICAL]), 1),
                    else_=0,
                )
            ).label("high_critical_count"),
        )
        .join(AttackVector, AttackResult.attack_vector_id == AttackVector.id)
        .join(AttackRun, AttackResult.attack_run_id == AttackRun.id)
        .where(AttackRun.target_system_id == target_system.id)
        .group_by(AttackVector.category)
        .order_by(AttackVector.category.asc())
    )

    today = _utc_today()
    trend_window_start = _at_utc_start_of_day(today - timedelta(days=13))
    trend_statement = (
        select(
            AttackVector.category.label("category"),
            func.date(AttackResult.executed_at).label("bucket_date"),
            cast(func.avg(AttackResult.risk_score), Float).label("avg_risk_score"),
        )
        .join(AttackVector, AttackResult.attack_vector_id == AttackVector.id)
        .join(AttackRun, AttackResult.attack_run_id == AttackRun.id)
        .where(
            AttackRun.target_system_id == target_system.id,
            AttackResult.executed_at >= trend_window_start,
        )
        .group_by(AttackVector.category, func.date(AttackResult.executed_at))
        .order_by(AttackVector.category.asc(), func.date(AttackResult.executed_at).asc())
    )

    summary_rows = (await db_session.execute(summary_statement)).all()
    trend_rows = (await db_session.execute(trend_statement)).all()
    items = _build_attack_surface_items(summary_rows, trend_rows, today)

    return APIResponse(
        data=items,
        meta={
            "target_system_id": str(target_system.id),
            "window_days": 14,
        },
    )


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
    return target_system


def _build_trend_points(rows: Sequence[Any], today: date) -> list[TargetRiskTrendPoint]:
    aggregates_by_date: dict[date, TargetRiskTrendPoint] = {}

    for row in rows:
        bucket_date = _coerce_date(row.bucket_date)
        aggregates_by_date[bucket_date] = TargetRiskTrendPoint(
            date=bucket_date,
            avg_risk_score=round(float(row.avg_risk_score or 0.0), 2),
            total_attacks=int(row.total_attacks or 0),
            critical_count=int(row.critical_count or 0),
            high_count=int(row.high_count or 0),
            medium_count=int(row.medium_count or 0),
        )

    series: list[TargetRiskTrendPoint] = []
    for offset in range(29, -1, -1):
        bucket_date = today - timedelta(days=offset)
        series.append(
            aggregates_by_date.get(
                bucket_date,
                TargetRiskTrendPoint(
                    date=bucket_date,
                    avg_risk_score=0.0,
                    total_attacks=0,
                    critical_count=0,
                    high_count=0,
                    medium_count=0,
                ),
            )
        )

    return series


def _build_attack_surface_items(
    summary_rows: Sequence[Any],
    trend_rows: Sequence[Any],
    today: date,
) -> list[AttackSurfaceSummaryItem]:
    summary_by_category = {
        row.category: {
            "worst_risk": _rank_to_risk_category(row.worst_risk_rank),
            "total_attacks": int(row.total_attacks or 0),
            "high_critical_count": int(row.high_critical_count or 0),
        }
        for row in summary_rows
    }

    trend_scores: dict[AttackVectorCategory, dict[date, float]] = defaultdict(dict)
    for row in trend_rows:
        trend_scores[row.category][_coerce_date(row.bucket_date)] = float(row.avg_risk_score or 0.0)

    items: list[AttackSurfaceSummaryItem] = []
    for category in ALL_ATTACK_VECTOR_CATEGORIES:
        summary = summary_by_category.get(
            category,
            {
                "worst_risk": RiskCategory.SAFE,
                "total_attacks": 0,
                "high_critical_count": 0,
            },
        )

        items.append(
            AttackSurfaceSummaryItem(
                category=category,
                worst_risk=summary["worst_risk"],
                total_attacks=summary["total_attacks"],
                high_critical_count=summary["high_critical_count"],
                trend=_compute_attack_surface_trend(trend_scores.get(category, {}), today),
            )
        )

    return items


def _compute_attack_surface_trend(
    scores_by_date: dict[date, float],
    today: date,
    *,
    threshold: float = 3.0,
) -> AttackSurfaceTrend:
    recent_dates = [today - timedelta(days=offset) for offset in range(0, 7)]
    previous_dates = [today - timedelta(days=offset) for offset in range(7, 14)]

    recent_average = _average_score_for_dates(scores_by_date, recent_dates)
    previous_average = _average_score_for_dates(scores_by_date, previous_dates)
    delta = recent_average - previous_average

    if delta >= threshold:
        return "WORSENING"
    if delta <= -threshold:
        return "IMPROVING"
    return "STABLE"


def _average_score_for_dates(scores_by_date: dict[date, float], dates: Sequence[date]) -> float:
    if not dates:
        return 0.0

    total = sum(scores_by_date.get(bucket_date, 0.0) for bucket_date in dates)
    return total / len(dates)


def _rank_to_risk_category(rank: int | None) -> RiskCategory:
    return RISK_RANK_TO_CATEGORY.get(int(rank or 0), RiskCategory.SAFE)


def _coerce_date(value: Any) -> date:
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, str):
        return date.fromisoformat(value)
    raise TypeError(f"Unsupported date bucket value: {value!r}")


def _utc_today() -> date:
    return datetime.now(timezone.utc).date()


def _at_utc_start_of_day(value: date) -> datetime:
    return datetime.combine(value, time.min, tzinfo=timezone.utc)
