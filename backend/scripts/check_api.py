from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import httpx

BACKEND_DIR = Path(__file__).resolve().parents[1]

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

ENDPOINTS = (
    ("/health", False),
    ("/api/v1/attack-runs/summary", True),
    ("/api/v1/attack-runs", True),
)


async def main() -> int:
    failed = False
    api_base_url = os.getenv("SHADOWLEDGER_API_URL", "http://localhost:8000").rstrip("/")
    bearer_token = os.getenv("SHADOWLEDGER_BEARER_TOKEN", "").strip()
    demo_auth_enabled = (
        os.getenv("ENVIRONMENT", "development").lower() == "development"
        and os.getenv("NEXT_PUBLIC_DEMO_AUTH", "").strip().lower() in {"1", "true", "yes", "on"}
    )
    headers = {"Accept": "application/json"}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    async with httpx.AsyncClient(timeout=5.0, follow_redirects=True, trust_env=False) as client:
        for path, protected in ENDPOINTS:
            url = f"{api_base_url}{path}"
            print(f"GET {url}")
            try:
                response = await _get_with_retries(client, url, headers)
            except Exception as exc:
                print(f"  status: ERROR")
                print(f"  summary: {exc}")
                failed = True
                continue

            print(f"  status: {response.status_code}")
            print(f"  summary: {_summarize_response(response)}")

            expecting_auth_challenge = protected and not bearer_token and not demo_auth_enabled
            if expecting_auth_challenge:
                if response.status_code != 401:
                    print("  expected: 401 because no Clerk session token was supplied")
                    failed = True
            elif not response.is_success:
                failed = True

    return 1 if failed else 0


async def _get_with_retries(
    client: httpx.AsyncClient,
    url: str,
    headers: dict[str, str],
) -> httpx.Response:
    last_error: Exception | None = None

    for attempt in range(1, 4):
        try:
            return await client.get(url, headers=headers)
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
    raise SystemExit(asyncio.run(main()))
