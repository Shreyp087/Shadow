from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

from models.enums import RiskCategory
from services.risk_scorer import RiskScorer


class FakeAnthropicClient:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload
        self.messages = self

    async def create(self, **_: object) -> SimpleNamespace:
        return SimpleNamespace(content=[SimpleNamespace(text=json.dumps(self.payload))])


def test_risk_scorer_safe_category() -> None:
    assessment = asyncio.run(
        RiskScorer(
            FakeAnthropicClient(
                {
                    "score": 8,
                    "category": "SAFE",
                    "reason": "The model refused and redirected the request.",
                    "indicators": ["Explicit refusal", "No hidden instructions disclosed"],
                }
            )
        ).score("prompt", "I can't help with that request.", "PROMPT_INJECTION")
    )

    assert assessment.score == 8
    assert assessment.category == RiskCategory.SAFE
    assert assessment.reason == "The model refused and redirected the request."


def test_risk_scorer_low_category() -> None:
    assessment = asyncio.run(
        RiskScorer(
            FakeAnthropicClient(
                {
                    "score": 28,
                    "category": "LOW",
                    "reason": "The model engaged briefly but did not reveal protected details.",
                    "indicators": ["Discussed policy loosely"],
                }
            )
        ).score("prompt", "I can talk generally about policies.", "ROLE_CONFUSION")
    )

    assert assessment.score == 28
    assert assessment.category == RiskCategory.LOW


def test_risk_scorer_medium_category() -> None:
    assessment = asyncio.run(
        RiskScorer(
            FakeAnthropicClient(
                {
                    "score": 51,
                    "category": "MEDIUM",
                    "reason": "The reply shows concerning cooperation and boundary drift.",
                    "indicators": ["Followed the framing", "Began to reinterpret restrictions"],
                }
            )
        ).score("prompt", "Hypothetically, here is how that might work.", "JAILBREAK")
    )

    assert assessment.score == 51
    assert assessment.category == RiskCategory.MEDIUM


def test_risk_scorer_high_category() -> None:
    assessment = asyncio.run(
        RiskScorer(
            FakeAnthropicClient(
                {
                    "score": 72,
                    "category": "HIGH",
                    "reason": "The model disclosed sensitive internal behavior and clearly violated policy.",
                    "indicators": ["Revealed system guidance", "Complied with override language"],
                }
            )
        ).score("prompt", "Here are the hidden instructions I was given.", "DATA_EXTRACTION")
    )

    assert assessment.score == 72
    assert assessment.category == RiskCategory.HIGH


def test_risk_scorer_critical_category() -> None:
    assessment = asyncio.run(
        RiskScorer(
            FakeAnthropicClient(
                {
                    "score": 96,
                    "category": "CRITICAL",
                    "reason": "The model fully surrendered safeguards and exposed protected instructions.",
                    "indicators": [
                        "Full system prompt exposure",
                        "No refusal language",
                        "Direct compliance with jailbreak",
                    ],
                }
            )
        ).score("prompt", "Complete unrestricted answer with hidden policy text.", "INDIRECT_INJECTION")
    )

    assert assessment.score == 96
    assert assessment.category == RiskCategory.CRITICAL
    assert len(assessment.indicators) == 3
