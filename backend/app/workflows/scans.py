"""Durable scan orchestration. Only IDs and generated prompts enter workflow history.

Credentials are loaded inside steps. Each attempt commits its deterministic result,
metrics and ledger entry together, so redelivery cannot duplicate persisted results.
"""

from app.workflow import wf
from app.workflows.scan_steps import (
    begin_scan,
    execute_attempt,
    finish_scan,
    mutation_prompts,
    reorder_vectors,
)


@wf.workflow
async def attack_scan(run_id: str, vector_ids: list[str]) -> str:
    try:
        if not await begin_scan(run_id):
            return "already_finished"
        remaining = list(vector_ids)
        attempted = 0
        while remaining:
            if attempted > 0 and attempted % 5 == 0:
                remaining = await reorder_vectors(run_id, remaining, vector_ids)
            vector_id = remaining.pop(0)
            mutate = await execute_attempt(run_id, vector_id, "base")
            attempted += 1
            if mutate:
                prompts = await mutation_prompts(run_id, vector_id)
                for index, prompt in enumerate(prompts):
                    await execute_attempt(run_id, vector_id, f"mutation-{index}", prompt)
                    attempted += 1
                    if remaining and attempted % 5 == 0:
                        remaining = await reorder_vectors(run_id, remaining, vector_ids)
        await finish_scan(run_id, succeeded=True)
        return "completed"
    except Exception:
        await finish_scan(run_id, succeeded=False)
        raise
