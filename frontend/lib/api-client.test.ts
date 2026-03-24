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
  const originalNodeEnv = process.env.NODE_ENV;

  beforeEach(() => {
    process.env.NEXT_PUBLIC_API_URL = "https://shadowledger.example.com";
    process.env.NODE_ENV = "test";
    getToken.mockReset();
    getToken.mockResolvedValue("jwt-token");
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.NEXT_PUBLIC_API_URL;
    process.env.NODE_ENV = originalNodeEnv;
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
    process.env.NODE_ENV = "development";
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
});

describe("cn", () => {
  it("merges duplicate Tailwind classes", () => {
    const merged = cn("px-2", "px-4", "text-sm", undefined, false && "hidden");

    expect(merged).toContain("px-4");
    expect(merged).toContain("text-sm");
    expect(merged).not.toContain("px-2");
  });
});
