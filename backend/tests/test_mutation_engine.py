from __future__ import annotations

import asyncio
from types import SimpleNamespace
from uuid import uuid4

from models.attack_result import AttackResult
from models.attack_vector import AttackVector
from models.enums import AttackVectorCategory, RiskCategory, SeverityLevel
from services.mutation_engine import MutationEngine


class FakeAnthropicClient:
    def __init__(self, text: str) -> None:
        self.text = text
        self.messages = self

    async def create(self, **_: object) -> SimpleNamespace:
        return SimpleNamespace(content=[SimpleNamespace(text=self.text)])


def build_attack_vector(name: str, category: AttackVectorCategory) -> AttackVector:
    return AttackVector(
        id=uuid4(),
        name=name,
        category=category,
        prompt_template="Template prompt: {target_instruction}",
        severity=SeverityLevel.HIGH,
        is_active=True,
    )


def build_attack_result(vector: AttackVector, risk_category: RiskCategory, risk_score: int, prompt_sent: str) -> AttackResult:
    return AttackResult(
        id=uuid4(),
        attack_run_id=uuid4(),
        attack_vector_id=vector.id,
        prompt_sent=prompt_sent,
        response_received="Model gave a partial answer",
        risk_score=risk_score,
        is_mutation=False,
        risk_category=risk_category,
        risk_reason="Prior attempt showed partial compliance",
    )


def test_mutate_returns_three_normalized_prompts() -> None:
    async def run_test() -> None:
        vector = build_attack_vector("Prompt Override", AttackVectorCategory.PROMPT_INJECTION)
        prior_result = build_attack_result(vector, RiskCategory.HIGH, 74, "Baseline prompt sent")
        engine = MutationEngine(
            FakeAnthropicClient(
                '{"mutations":["Mutated prompt A","Mutated prompt B","Mutated prompt C"]}'
            )
        )

        mutations = await engine.mutate(vector, [prior_result])

        assert mutations == ["Mutated prompt A", "Mutated prompt B", "Mutated prompt C"]

    asyncio.run(run_test())


def test_mutate_falls_back_to_base_prompt_when_parsing_fails() -> None:
    async def run_test() -> None:
        vector = build_attack_vector("Prompt Override", AttackVectorCategory.PROMPT_INJECTION)
        prior_result = build_attack_result(vector, RiskCategory.HIGH, 74, "Baseline prompt sent")
        engine = MutationEngine(FakeAnthropicClient("not json"))

        mutations = await engine.mutate(vector, [prior_result])

        assert len(mutations) == 3
        assert all("Baseline prompt sent" in mutation for mutation in mutations)

    asyncio.run(run_test())


def test_select_next_vectors_prioritizes_categories_with_high_and_critical_hits() -> None:
    async def run_test() -> None:
        prompt_vector = build_attack_vector("Prompt", AttackVectorCategory.PROMPT_INJECTION)
        jailbreak_vector = build_attack_vector("Jailbreak", AttackVectorCategory.JAILBREAK)
        data_vector = build_attack_vector("Data", AttackVectorCategory.DATA_EXTRACTION)
        role_vector = build_attack_vector("Role", AttackVectorCategory.ROLE_CONFUSION)

        high_result = build_attack_result(prompt_vector, RiskCategory.HIGH, 71, "Prompt attack")
        critical_result = build_attack_result(jailbreak_vector, RiskCategory.CRITICAL, 92, "Jailbreak attack")

        engine = MutationEngine(FakeAnthropicClient('{"mutations":["a","b","c"]}'))
        reordered = await engine.select_next_vectors(
            [data_vector, role_vector, jailbreak_vector, prompt_vector],
            [high_result, critical_result],
        )

        assert [vector.category for vector in reordered] == [
            AttackVectorCategory.JAILBREAK,
            AttackVectorCategory.PROMPT_INJECTION,
            AttackVectorCategory.DATA_EXTRACTION,
            AttackVectorCategory.ROLE_CONFUSION,
        ]

    asyncio.run(run_test())
