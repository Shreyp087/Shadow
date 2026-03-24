from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import httpx

BACKEND_DIR = Path(__file__).resolve().parents[1]

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

ENDPOINTS = (
    "http://localhost:8000/health",
    "http://localhost:8000/api/v1/attack-runs/summary",
    "http://localhost:8000/api/v1/attack-runs",
)


async def main() -> None:
    async with httpx.AsyncClient(timeout=5.0, follow_redirects=True, trust_env=False) as client:
        for url in ENDPOINTS:
            print(f"GET {url}")
            try:
                response = await _get_with_retries(client, url)
            except Exception as exc:
                print(f"  status: ERROR")
                print(f"  summary: {exc}")
                continue

            print(f"  status: {response.status_code}")
            print(f"  summary: {_summarize_response(response)}")


async def _get_with_retries(client: httpx.AsyncClient, url: str) -> httpx.Response:
    last_error: Exception | None = None

    for attempt in range(1, 4):
        try:
            return await client.get(url, headers={"Accept": "application/json"})
        except httpx.RequestError as exc:
            last_error = exc
            if attempt == 3:
                break
            await asyncio.sleep(0.5)

    if last_error is None:
        raise RuntimeError("Request failed for an unknown reason.")

    raise last_error


def _summarize_response(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except json.JSONDecodeError:
        text = response.text.strip()
        return text[:200] if text else "<empty response>"

    if isinstance(payload, dict) and payload.get("data") is not None:
        data = payload["data"]
        meta = payload.get("meta") or {}

        if isinstance(data, dict) and {"total_scans", "vulnerabilities_found"} <= data.keys():
            total_results = meta.get("total_results", "unknown")
            return (
                f"runs={data.get('total_scans')} | results={total_results} | "
                f"vulnerabilities={data.get('vulnerabilities_found')}"
            )

        if isinstance(data, list):
            return f"items={len(data)}"

        if isinstance(data, dict) and {"status", "version"} <= data.keys():
            return f"status={data.get('status')} | version={data.get('version')} | db={data.get('db')}"

        return json.dumps(data)[:200]

    if isinstance(payload, dict) and {"status", "version"} <= payload.keys():
        return f"status={payload.get('status')} | version={payload.get('version')} | db={payload.get('db')}"

    if isinstance(payload, list):
        return f"items={len(payload)}"

    return json.dumps(payload)[:200]


if __name__ == "__main__":
    asyncio.run(main())
