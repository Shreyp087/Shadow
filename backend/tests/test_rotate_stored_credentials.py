from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from scripts import rotate_target_keys as rotation_script


class FakeScalarResult:
    def __init__(self, items: list[SimpleNamespace]) -> None:
        self._items = items

    def scalars(self) -> "FakeScalarResult":
        return self

    def all(self) -> list[SimpleNamespace]:
        return self._items


class FakeSession:
    def __init__(self, result_sets: list[list[SimpleNamespace]]) -> None:
        self._result_sets = list(result_sets)
        self.commit_calls = 0

    async def __aenter__(self) -> "FakeSession":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def execute(self, _statement: object) -> FakeScalarResult:
        return FakeScalarResult(self._result_sets.pop(0))

    async def commit(self) -> None:
        self.commit_calls += 1


def test_rotation_reencrypts_target_and_non_null_llm_role_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_one = SimpleNamespace(api_key_encrypted="target-secret-one")
    target_two = SimpleNamespace(api_key_encrypted="target-secret-two")
    attacker = SimpleNamespace(api_key_encrypted="attacker-secret")
    mutator_without_key = SimpleNamespace(api_key_encrypted=None)
    judge = SimpleNamespace(api_key_encrypted="judge-secret")
    session = FakeSession(
        [[target_one, target_two], [attacker, mutator_without_key, judge]]
    )
    rotated_values: list[str] = []

    monkeypatch.setenv("ENCRYPTION_KEY_PREVIOUS", "old-fernet-key")
    monkeypatch.setattr(rotation_script, "AsyncSessionLocal", lambda: session)

    def fake_rotate_value(value: str) -> str:
        rotated_values.append(value)
        return f"rotated-{len(rotated_values)}"

    monkeypatch.setattr(rotation_script, "rotate_value", fake_rotate_value)

    summary = asyncio.run(rotation_script.rotate_stored_credentials())

    assert summary.target_credentials == 2
    assert summary.llm_role_credentials == 2
    assert summary.total == 4
    assert session.commit_calls == 1
    assert rotated_values == [
        "target-secret-one",
        "target-secret-two",
        "attacker-secret",
        "judge-secret",
    ]
    assert target_one.api_key_encrypted == "rotated-1"
    assert target_two.api_key_encrypted == "rotated-2"
    assert attacker.api_key_encrypted == "rotated-3"
    assert mutator_without_key.api_key_encrypted is None
    assert judge.api_key_encrypted == "rotated-4"


def test_rotation_requires_previous_key_before_opening_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ENCRYPTION_KEY_PREVIOUS", raising=False)
    session_factory_called = False

    def fake_session_factory() -> FakeSession:
        nonlocal session_factory_called
        session_factory_called = True
        return FakeSession([[], []])

    monkeypatch.setattr(rotation_script, "AsyncSessionLocal", fake_session_factory)

    with pytest.raises(RuntimeError, match="ENCRYPTION_KEY_PREVIOUS"):
        asyncio.run(rotation_script.rotate_stored_credentials())

    assert session_factory_called is False


def test_rotation_output_reports_counts_without_credentials(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    session = FakeSession(
        [
            [SimpleNamespace(api_key_encrypted="target-output-secret")],
            [SimpleNamespace(api_key_encrypted="role-output-secret")],
        ]
    )
    monkeypatch.setenv("ENCRYPTION_KEY_PREVIOUS", "old-fernet-key")
    monkeypatch.setattr(rotation_script, "AsyncSessionLocal", lambda: session)
    monkeypatch.setattr(rotation_script, "rotate_value", lambda _value: "ciphertext")

    asyncio.run(rotation_script.main())

    output = capsys.readouterr().out
    assert "Rotated target credentials: 1" in output
    assert "Rotated LLM role credentials: 1" in output
    assert "Rotated credentials total: 2" in output
    assert "target-output-secret" not in output
    assert "role-output-secret" not in output
    assert "ciphertext" not in output
