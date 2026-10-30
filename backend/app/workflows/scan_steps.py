"""Sandbox-safe step declarations; side effects are imported only during execution."""
from app.workflow import wf


@wf.step
async def begin_scan(run_id: str) -> bool:
    from app.workflows.scan_runtime import begin_scan as execute
    return await execute(run_id)


@wf.step(max_retries=2)
async def execute_attempt(run_id: str, vector_id: str, attempt: str, prompt: str | None = None) -> bool:
    from app.workflows.scan_runtime import execute_attempt as execute
    return await execute(run_id, vector_id, attempt, prompt)


@wf.step(max_retries=2)
async def mutation_prompts(run_id: str, vector_id: str) -> list[str]:
    from app.workflows.scan_runtime import mutation_prompts as execute
    return await execute(run_id, vector_id)


@wf.step
async def reorder_vectors(run_id: str, remaining: list[str], all_vectors: list[str]) -> list[str]:
    from app.workflows.scan_runtime import reorder_vectors as execute
    return await execute(run_id, remaining, all_vectors)


@wf.step
async def finish_scan(run_id: str, *, succeeded: bool) -> None:
    from app.workflows.scan_runtime import finish_scan as execute
    await execute(run_id, succeeded=succeeded)
