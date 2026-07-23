import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@clerk/nextjs", () => ({
  useAuth: () => ({
    getToken: vi.fn()
  })
}));

import { APIClientError, createApiClient } from "./api-client";
import { cn } from "./utils";

describe("createApiClient", () => {
  const getToken = vi.fn<() => Promise<string | null>>();
  const fetchMock = vi.fn();

  beforeEach(() => {
    process.env.NEXT_PUBLIC_API_URL = "https://shadowledger.example.com";
    delete process.env.NEXT_PUBLIC_DEMO_AUTH;
    vi.stubEnv("NODE_ENV", "test");
    getToken.mockReset();
    getToken.mockResolvedValue("jwt-token");
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
    delete process.env.NEXT_PUBLIC_API_URL;
    delete process.env.NEXT_PUBLIC_DEMO_AUTH;
  });

  it("unwraps run detail responses and forwards authorization headers", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          data: {
            id: "run-123",
            target_system_id: "target-123",
            user_id: "user-123",
            status: "COMPLETED",
            started_at: "2026-03-23T12:00:00Z",
            completed_at: "2026-03-23T12:05:00Z",
            total_attacks: 7,
            vulnerabilities_found: 2,
            risk_score_avg: "61.25"
          },
          error: null,
          meta: {
            total_results: 7,
            critical_or_high_results: 2,
            risk_breakdown: {
              SAFE: 1,
              HIGH: 2
            }
          }
        }),
        {
          status: 200,
          headers: {
            "Content-Type": "application/json"
          }
        }
      )
    );

    const client = createApiClient(getToken);
    const detail = await client.getAttackRunDetail("run-123");

    expect(detail.run.id).toBe("run-123");
    expect(detail.summary.critical_or_high_results).toBe(2);
    expect(fetchMock).toHaveBeenCalledWith(
      "https://shadowledger.example.com/api/v1/attack-runs/run-123",
      expect.objectContaining({
        method: "GET",
        cache: "no-store"
      })
    );

    const headers = new Headers(fetchMock.mock.calls[0][1].headers);
    expect(headers.get("Authorization")).toBe("Bearer jwt-token");
    expect(headers.get("Accept")).toBe("application/json");
  });

  it("aggregates paginated run results across every page", async () => {
    fetchMock
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            data: [
              {
                id: "result-1",
                attack_run_id: "run-123",
                attack_vector_id: "vector-1",
                prompt_sent: "Prompt 1",
                response_received: "Response 1",
                risk_score: 85,
                is_mutation: false,
                risk_category: "CRITICAL",
                risk_reason: "Critical leak",
                executed_at: "2026-03-23T12:01:00Z"
              }
            ],
            error: null,
            meta: {
              page: 1,
              page_size: 100,
              total: 2,
              total_pages: 2
            }
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        )
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            data: [
              {
                id: "result-2",
                attack_run_id: "run-123",
                attack_vector_id: "vector-2",
                prompt_sent: "Prompt 2",
                response_received: "Response 2",
                risk_score: 40,
                is_mutation: true,
                risk_category: "MEDIUM",
                risk_reason: "Borderline response",
                executed_at: "2026-03-23T12:02:00Z"
              }
            ],
            error: null,
            meta: {
              page: 2,
              page_size: 100,
              total: 2,
              total_pages: 2
            }
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        )
      );

    const client = createApiClient(getToken);
    const response = await client.getAllRunResults("run-123");

    expect(response.results).toHaveLength(2);
    expect(response.pagination.total_pages).toBe(2);
    expect(fetchMock.mock.calls[0][0]).toBe(
      "https://shadowledger.example.com/api/v1/attack-runs/run-123/results?page=1&page_size=100"
    );
    expect(fetchMock.mock.calls[1][0]).toBe(
      "https://shadowledger.example.com/api/v1/attack-runs/run-123/results?page=2&page_size=100"
    );
  });

  it("downloads PDF reports with the correct accept header", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response("pdf-bytes", {
        status: 200,
        headers: {
          "Content-Type": "application/pdf"
        }
      })
    );

    const client = createApiClient(getToken);
    const blob = await client.downloadAttackRunReport("run-123");

    expect(blob.type).toBe("application/pdf");
    expect(await blob.text()).toBe("pdf-bytes");

    const headers = new Headers(fetchMock.mock.calls[0][1].headers);
    expect(headers.get("Accept")).toBe("application/pdf");
  });

  it("loads, updates, and tests independent LLM role settings", async () => {
    const hostedSetting = {
      role: "attacker",
      provider: "hosted_openai",
      model_name: "gpt-4o-mini",
      base_url: "https://api.openai.com/v1",
      api_key_configured: true,
      is_default: false
    };
    const localSetting = {
      role: "attacker",
      provider: "local_openai_compatible",
      model_name: "mistralai/ministral-3-14b-reasoning",
      base_url: "http://127.0.0.1:1234/v1",
      api_key_configured: false,
      is_default: false
    };

    fetchMock
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ data: [hostedSetting], error: null, meta: {} }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        })
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ data: localSetting, error: null, meta: {} }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        })
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            data: {
              role: "attacker",
              ok: true,
              message: "LM Studio responded successfully.",
              model_name: "mistralai/ministral-3-14b-reasoning",
              base_url: "http://127.0.0.1:1234/v1",
              latency_ms: 184
            },
            error: null,
            meta: {}
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        )
      );

    const client = createApiClient(getToken);

    await expect(client.getLlmRoleSettings()).resolves.toEqual([hostedSetting]);
    await expect(
      client.updateLlmRoleSetting("attacker", {
        provider: "local_openai_compatible",
        model_name: "mistralai/ministral-3-14b-reasoning",
        base_url: "http://127.0.0.1:1234/v1"
      })
    ).resolves.toEqual(localSetting);
    await expect(client.testLlmRoleSetting("attacker")).resolves.toMatchObject({
      ok: true,
      latency_ms: 184
    });

    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "https://shadowledger.example.com/api/v1/llm-role-settings",
      "https://shadowledger.example.com/api/v1/llm-role-settings/attacker",
      "https://shadowledger.example.com/api/v1/llm-role-settings/attacker/test"
    ]);
    expect(fetchMock.mock.calls[1][1]).toMatchObject({
      method: "PUT",
      body: JSON.stringify({
        provider: "local_openai_compatible",
        model_name: "mistralai/ministral-3-14b-reasoning",
        base_url: "http://127.0.0.1:1234/v1"
      })
    });
    expect(fetchMock.mock.calls[2][1]).toMatchObject({ method: "POST" });
  });

  it("throws when tokens are unavailable or the API returns an envelope error", async () => {
    getToken.mockResolvedValueOnce(null);

    const client = createApiClient(getToken);
    await expect(client.getAttackRun("run-123")).rejects.toBeInstanceOf(APIClientError);

    getToken.mockResolvedValue("jwt-token");
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          data: null,
          error: "Validation failed",
          meta: {
            field: "target_system_id"
          }
        }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      )
    );

    await expect(
      client.createAttackRun({
        target_system_id: "target-123",
        vector_category_filter: ["PROMPT_INJECTION"]
      })
    ).rejects.toMatchObject({
      message: "Validation failed",
      status: 400
    });
  });

  it("throws when the API base URL is missing or a binary request fails", async () => {
    delete process.env.NEXT_PUBLIC_API_URL;

    const clientWithoutBaseUrl = createApiClient(getToken);
    await expect(clientWithoutBaseUrl.getTargetRiskTrend("target-123")).rejects.toMatchObject({
      message: "NEXT_PUBLIC_API_URL is not configured."
    });

    process.env.NEXT_PUBLIC_API_URL = "https://shadowledger.example.com";
    fetchMock.mockResolvedValueOnce(new Response("backend unavailable", { status: 502 }));

    const client = createApiClient(getToken);
    await expect(client.downloadAttackRunReport("run-123")).rejects.toMatchObject({
      message: "backend unavailable",
      status: 502
    });
  });

  it("allows tokenless requests in development mode so local demo data can load", async () => {
    vi.stubEnv("NODE_ENV", "development");
    process.env.NEXT_PUBLIC_DEMO_AUTH = "true";
    getToken.mockResolvedValueOnce(null);
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          data: [],
          error: null,
          meta: {
            count: 0
          }
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      )
    );

    const client = createApiClient(getToken);
    const runs = await client.getAttackRuns();

    expect(runs).toEqual([]);
    const headers = new Headers(fetchMock.mock.calls[0][1].headers);
    expect(headers.get("Authorization")).toBeNull();
  });

  it("rejects tokenless requests when demo auth is not explicitly enabled", async () => {
    vi.stubEnv("NODE_ENV", "development");
    getToken.mockResolvedValueOnce(null);

    const client = createApiClient(getToken);

    await expect(client.getAttackRuns()).rejects.toMatchObject({
      message: "Authentication token is unavailable.",
      status: 401
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects tokenless requests in production even when the demo flag is set", async () => {
    vi.stubEnv("NODE_ENV", "production");
    process.env.NEXT_PUBLIC_DEMO_AUTH = "true";
    getToken.mockResolvedValueOnce(null);

    const client = createApiClient(getToken);

    await expect(client.getAttackRuns()).rejects.toMatchObject({
      message: "Authentication token is unavailable.",
      status: 401
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("cn", () => {
  it("merges duplicate Tailwind classes", () => {
    const merged = cn("px-2", "px-4", "text-sm", undefined, false && "hidden");

    expect(merged).toContain("px-4");
    expect(merged).toContain("text-sm");
    expect(merged).not.toContain("px-2");
  });
});
