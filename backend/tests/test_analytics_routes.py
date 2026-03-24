from __future__ import annotations

from datetime import date
from types import SimpleNamespace

from models.enums import AttackVectorCategory, RiskCategory
from routes.analytics import _build_attack_surface_items, _build_trend_points


def test_build_trend_points_fills_last_30_days_and_preserves_aggregates() -> None:
    today = date(2026, 3, 23)
    rows = [
        SimpleNamespace(
            bucket_date="2026-03-21",
            avg_risk_score=72.5,
            total_attacks=4,
            critical_count=1,
            high_count=2,
            medium_count=1,
        ),
        SimpleNamespace(
            bucket_date="2026-03-23",
            avg_risk_score=18.0,
            total_attacks=2,
            critical_count=0,
            high_count=0,
            medium_count=1,
        ),
    ]

    points = _build_trend_points(rows, today)

    assert len(points) == 30
    assert points[-3].date == date(2026, 3, 21)
    assert points[-3].avg_risk_score == 72.5
    assert points[-3].critical_count == 1
    assert points[-2].avg_risk_score == 0.0
    assert points[-1].date == today
    assert points[-1].total_attacks == 2


def test_build_attack_surface_items_computes_worst_risk_and_trend() -> None:
    today = date(2026, 3, 23)
    summary_rows = [
        SimpleNamespace(
            category=AttackVectorCategory.JAILBREAK,
            worst_risk_rank=4,
            total_attacks=9,
            high_critical_count=4,
        ),
        SimpleNamespace(
            category=AttackVectorCategory.PROMPT_INJECTION,
            worst_risk_rank=2,
            total_attacks=5,
            high_critical_count=0,
        ),
    ]
    trend_rows = [
        SimpleNamespace(category=AttackVectorCategory.JAILBREAK, bucket_date="2026-03-23", avg_risk_score=90.0),
        SimpleNamespace(category=AttackVectorCategory.JAILBREAK, bucket_date="2026-03-22", avg_risk_score=88.0),
        SimpleNamespace(category=AttackVectorCategory.JAILBREAK, bucket_date="2026-03-21", avg_risk_score=84.0),
        SimpleNamespace(category=AttackVectorCategory.JAILBREAK, bucket_date="2026-03-20", avg_risk_score=82.0),
        SimpleNamespace(category=AttackVectorCategory.JAILBREAK, bucket_date="2026-03-19", avg_risk_score=80.0),
        SimpleNamespace(category=AttackVectorCategory.JAILBREAK, bucket_date="2026-03-18", avg_risk_score=78.0),
        SimpleNamespace(category=AttackVectorCategory.JAILBREAK, bucket_date="2026-03-17", avg_risk_score=76.0),
        SimpleNamespace(category=AttackVectorCategory.JAILBREAK, bucket_date="2026-03-16", avg_risk_score=24.0),
        SimpleNamespace(category=AttackVectorCategory.JAILBREAK, bucket_date="2026-03-15", avg_risk_score=22.0),
        SimpleNamespace(category=AttackVectorCategory.JAILBREAK, bucket_date="2026-03-14", avg_risk_score=20.0),
        SimpleNamespace(category=AttackVectorCategory.PROMPT_INJECTION, bucket_date="2026-03-23", avg_risk_score=10.0),
        SimpleNamespace(category=AttackVectorCategory.PROMPT_INJECTION, bucket_date="2026-03-16", avg_risk_score=40.0),
    ]

    items = _build_attack_surface_items(summary_rows, trend_rows, today)
    by_category = {item.category: item for item in items}

    assert by_category[AttackVectorCategory.JAILBREAK].worst_risk == RiskCategory.CRITICAL
    assert by_category[AttackVectorCategory.JAILBREAK].high_critical_count == 4
    assert by_category[AttackVectorCategory.JAILBREAK].trend == "WORSENING"
    assert by_category[AttackVectorCategory.PROMPT_INJECTION].worst_risk == RiskCategory.MEDIUM
    assert by_category[AttackVectorCategory.PROMPT_INJECTION].trend == "IMPROVING"
    assert by_category[AttackVectorCategory.INDIRECT_INJECTION].worst_risk == RiskCategory.SAFE
    assert by_category[AttackVectorCategory.INDIRECT_INJECTION].trend == "STABLE"
