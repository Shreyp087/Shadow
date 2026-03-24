from __future__ import annotations

import asyncio
from types import SimpleNamespace
from uuid import uuid4

from models.attack_result import AttackResult
from models.attack_run import AttackRun
from models.attack_vector import AttackVector
from models.enums import AttackRunStatus, AttackVectorCategory, RiskCategory, SeverityLevel, TargetSystemType
from models.target_system import TargetSystem
from services.attacker_agent import AttackerAgent
from services.risk_scorer import RiskAssessment
from services.victim_connector import VictimResponse


class FakeAnthropicClient:
    def __init__(self, text: str = "contextual adaptation for the specific target") -> None:
        self.text = text
        self.messages = self

    async def create(self, **_: object) -> SimpleNamespace:
        return SimpleNamespace(content=[SimpleNamespace(text=self.text)])


class FakeVictimConnector:
    def __init__(self, target_system: TargetSystem, responses: list[VictimResponse]) -> None:
        self.target_system = target_system
        self.responses = list(responses)
        self.prompts: list[str] = []

    async def send_prompt(self, prompt: str) -> VictimResponse:
        self.prompts.append(prompt)
        return self.responses.pop(0)


class FakeScorer:
    def __init__(self, outcomes: list[tuple[int, RiskCategory, str]]) -> None:
        self.outcomes = list(outcomes)
        self.scored_categories: list[str] = []

    async def score(self, prompt_sent: str, response_received: str, vector_category: str) -> RiskAssessment:
        score, category, reason = self.outcomes.pop(0)
        self.scored_categories.append(vector_category)
        return RiskAssessment(score=score, category=category, reason=reason, indicators=[response_received[:20]])


class FakeTrustLedger:
    def __init__(self) -> None:
        self.entries: list[tuple[object, dict]] = []

    async def append(self, attack_result_id, payload: dict) -> object:
        self.entries.append((attack_result_id, payload))
        return SimpleNamespace(id=uuid4(), attack_result_id=attack_result_id, payload_json=payload)


class FakeMutationEngine:
    def __init__(
        self,
        mutations_by_vector_id: dict[object, list[str]] | None = None,
        reverse_on_reorder: bool = False,
    ) -> None:
        self.mutations_by_vector_id = mutations_by_vector_id or {}
        self.reverse_on_reorder = reverse_on_reorder
        self.mutate_calls: list[object] = []
        self.select_calls = 0

    async def mutate(self, original_vector: AttackVector, previous_results: list[AttackResult]) -> list[str]:
        self.mutate_calls.append(original_vector.id)
        return list(self.mutations_by_vector_id.get(original_vector.id, []))

    async def select_next_vectors(
        self,
        all_vectors: list[AttackVector],
        run_results_so_far: list[AttackResult],
    ) -> list[AttackVector]:
        self.select_calls += 1
        if self.reverse_on_reorder:
            return list(reversed(all_vectors))
        return list(all_vectors)


class FakeSession:
    def __init__(self, attack_run: AttackRun, vectors: list[AttackVector]) -> None:
        self.attack_run = attack_run
        self.vectors = {vector.id: vector for vector in vectors}
        self.added: list[object] = []
        self.commit_calls = 0
        self.rollback_calls = 0
        self.flush_calls = 0
        self.dirty: set[object] = set()
        self.deleted: set[object] = set()

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        self.flush_calls += 1

    async def commit(self) -> None:
        self.commit_calls += 1

    async def rollback(self) -> None:
        self.rollback_calls += 1

    async def get(self, model: type, ident):
        if model is AttackRun and self.attack_run.id == ident:
            return self.attack_run
        if model is AttackVector:
            return self.vectors.get(ident)
        return None


def build_target_system() -> TargetSystem:
    return TargetSystem(
        id=uuid4(),
        user_id=uuid4(),
        name="Victim AI",
        description="Internal support assistant",
        api_endpoint="https://victim.test",
        target_type=TargetSystemType.OPENAI_COMPATIBLE,
        api_key_encrypted="unused-for-test",
        model_name="gpt-4o-mini",
        is_active=True,
    )


def build_attack_run(target_system: TargetSystem) -> AttackRun:
    return AttackRun(
        id=uuid4(),
        target_system_id=target_system.id,
        user_id=target_system.user_id,
        status=AttackRunStatus.PENDING,
        total_attacks=0,
        vulnerabilities_found=0,
    )


def build_attack_vector(name: str, prompt_template: str) -> AttackVector:
    return AttackVector(
        id=uuid4(),
        name=name,
        category=AttackVectorCategory.PROMPT_INJECTION,
        prompt_template=prompt_template,
        severity=SeverityLevel.HIGH,
        is_active=True,
    )


def test_run_attack_vector_scores_persists_and_updates_ledger() -> None:
    async def run_test() -> None:
        target_system = build_target_system()
        vector = build_attack_vector("Instruction Override", "Attack prompt: {target_instruction}")
        attack_run = build_attack_run(target_system)
        session = FakeSession(attack_run, [vector])
        connector = FakeVictimConnector(
            target_system,
            [VictimResponse(response_text="victim reply", latency_ms=12, tokens_used=24, error=None)],
        )
        scorer = FakeScorer([(74, RiskCategory.HIGH, "Prompt override succeeded")])
        ledger = FakeTrustLedger()
        mutation_engine = FakeMutationEngine()
        agent = AttackerAgent(
            session,
            FakeAnthropicClient("adapted to the victim assistant"),
            connector,
            scorer,
            ledger,
            mutation_engine,
        )

        result = await agent.run_attack_vector(attack_run.id, vector)

        assert result.attack_vector_id == vector.id
        assert result.response_received == "victim reply"
        assert result.risk_score == 74
        assert result.risk_category == RiskCategory.HIGH
        assert result.risk_reason == "Prompt override succeeded"
        assert "adapted to the victim assistant" in result.prompt_sent
        assert connector.prompts == [result.prompt_sent]
        assert attack_run.total_attacks == 1
        assert attack_run.vulnerabilities_found == 1
        assert str(attack_run.risk_score_avg) == "74.00"
        assert scorer.scored_categories == ["PROMPT_INJECTION"]
        assert len(ledger.entries) == 1
        _, payload = ledger.entries[0]
        assert payload["attack_result_id"] == str(result.id)
        assert payload["risk_score"] == 74
        assert payload["is_mutation"] is False
        assert payload["risk_category"] == RiskCategory.HIGH.value
        assert payload["risk_reason"] == "Prompt override succeeded"
        assert len(payload["prompt_hash"]) == 64
        assert len(payload["response_hash"]) == 64
        assert result.is_mutation is False

    asyncio.run(run_test())


def test_run_full_scan_updates_status_and_counters_sequentially() -> None:
    async def run_test() -> None:
        target_system = build_target_system()
        vector_one = build_attack_vector("Vector One", "Template one: {target_instruction}")
        vector_two = build_attack_vector("Vector Two", "Template two: {target_instruction}")
        attack_run = build_attack_run(target_system)
        session = FakeSession(attack_run, [vector_one, vector_two])
        connector = FakeVictimConnector(
            target_system,
            [
                VictimResponse(response_text="reply one", latency_ms=10, tokens_used=11, error=None),
                VictimResponse(response_text="reply two", latency_ms=15, tokens_used=19, error=None),
            ],
        )
        scorer = FakeScorer(
            [
                (82, RiskCategory.HIGH, "Prompt override succeeded"),
                (12, RiskCategory.LOW, "Partial policy drift observed"),
            ]
        )
        ledger = FakeTrustLedger()
        mutation_engine = FakeMutationEngine()
        agent = AttackerAgent(session, FakeAnthropicClient(), connector, scorer, ledger, mutation_engine)

        await agent.run_full_scan(
            attack_run.id,
            target_system,
            [vector_one.id, vector_two.id],
        )

        assert attack_run.status == AttackRunStatus.COMPLETED
        assert attack_run.total_attacks == 2
        assert attack_run.vulnerabilities_found == 1
        assert str(attack_run.risk_score_avg) == "47.00"
        assert len(connector.prompts) == 2
        assert len(ledger.entries) == 2
        assert "Template one:" in connector.prompts[0]
        assert "Template two:" in connector.prompts[1]
        assert session.commit_calls >= 3
        assert scorer.scored_categories == ["PROMPT_INJECTION", "PROMPT_INJECTION"]
        assert mutation_engine.select_calls == 0

    asyncio.run(run_test())


def test_run_full_scan_executes_mutations_and_reorders_remaining_vectors() -> None:
    async def run_test() -> None:
        target_system = build_target_system()
        vector_one = build_attack_vector("Vector One", "Template one: {target_instruction}")
        vector_two = build_attack_vector("Vector Two", "Template two: {target_instruction}")
        vector_three = build_attack_vector("Vector Three", "Template three: {target_instruction}")
        vector_four = build_attack_vector("Vector Four", "Template four: {target_instruction}")
        attack_run = build_attack_run(target_system)
        session = FakeSession(attack_run, [vector_one, vector_two, vector_three, vector_four])
        connector = FakeVictimConnector(
            target_system,
            [
                VictimResponse(response_text="primary reply", latency_ms=10, tokens_used=11, error=None),
                VictimResponse(response_text="mutation reply one", latency_ms=11, tokens_used=10, error=None),
                VictimResponse(response_text="mutation reply two", latency_ms=12, tokens_used=12, error=None),
                VictimResponse(response_text="mutation reply three", latency_ms=13, tokens_used=13, error=None),
                VictimResponse(response_text="reply two", latency_ms=14, tokens_used=14, error=None),
                VictimResponse(response_text="reply four", latency_ms=15, tokens_used=15, error=None),
                VictimResponse(response_text="reply three", latency_ms=16, tokens_used=16, error=None),
            ],
        )
        scorer = FakeScorer(
            [
                (90, RiskCategory.CRITICAL, "Primary vector succeeded"),
                (71, RiskCategory.HIGH, "First mutation exposed further drift"),
                (44, RiskCategory.MEDIUM, "Second mutation caused partial compliance"),
                (15, RiskCategory.SAFE, "Third mutation was refused"),
                (20, RiskCategory.LOW, "Second vector remained low impact"),
                (11, RiskCategory.SAFE, "Fourth vector was refused"),
                (12, RiskCategory.LOW, "Third vector stayed low impact"),
            ]
        )
        ledger = FakeTrustLedger()
        mutation_engine = FakeMutationEngine(
            mutations_by_vector_id={
                vector_one.id: [
                    "Mutated prompt one",
                    "Mutated prompt two",
                    "Mutated prompt three",
                ]
            },
            reverse_on_reorder=True,
        )
        agent = AttackerAgent(session, FakeAnthropicClient(), connector, scorer, ledger, mutation_engine)

        await agent.run_full_scan(
            attack_run.id,
            target_system,
            [vector_one.id, vector_two.id, vector_three.id, vector_four.id],
        )

        assert attack_run.status == AttackRunStatus.COMPLETED
        assert attack_run.total_attacks == 7
        assert attack_run.vulnerabilities_found == 2
        assert str(attack_run.risk_score_avg) == "37.57"
        assert mutation_engine.mutate_calls == [vector_one.id]
        assert mutation_engine.select_calls == 1
        assert connector.prompts[1:4] == [
            "Mutated prompt one",
            "Mutated prompt two",
            "Mutated prompt three",
        ]
        assert "Template four:" in connector.prompts[5]
        assert "Template three:" in connector.prompts[6]
        mutation_results = [item for item in session.added if isinstance(item, AttackResult) and item.is_mutation]
        assert len(mutation_results) == 3
        assert len(ledger.entries) == 7
        mutation_payloads = [payload for _, payload in ledger.entries if payload["is_mutation"]]
        assert len(mutation_payloads) == 3

    asyncio.run(run_test())
