"use client";

import { useMemo } from "react";

import { useAppAuth } from "@/components/app-auth-provider";
import { isLocalDemoAuthEnabled } from "@/lib/auth-mode";
import type {
  APIResponse,
  APIResponseWithMeta,
  AttackResultResponse,
  AttackRunResponse,
  AttackRunSummaryMeta,
  AttackRunsSummaryResponse,
  AttackSurfaceSummaryItem,
  CreateAttackRunRequest,
  CreateTargetSystemRequest,
  LLMConnectionTestResponse,
  LLMRole,
  LLMRoleSettingResponse,
  PaginationMeta,
  TargetRiskTrendPoint,
  TargetSystemResponse,
  UpdateLLMRoleSettingRequest
} from "@/types/api";

type TokenGetter = ReturnType<typeof useAppAuth>["getToken"];

export class APIClientError extends Error {
  status: number;
  meta: Record<string, unknown>;

  constructor(message: string, status: number, meta: Record<string, unknown> = {}) {
    super(message);
    this.name = "APIClientError";
    this.status = status;
    this.meta = meta;
  }
}

function getApiBaseUrl() {
  const apiUrl = process.env.NEXT_PUBLIC_API_URL;

  if (!apiUrl) {
    throw new APIClientError("NEXT_PUBLIC_API_URL is not configured.", 500);
  }

  return apiUrl.replace(/\/$/, "");
}

export function buildApiUrl(path: string) {
  if (/^https?:\/\//.test(path)) {
    return path;
  }

  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  return `${getApiBaseUrl()}${normalizedPath}`;
}

async function buildAuthHeaders(init: RequestInit, getToken: TokenGetter, accept: string) {
  const token = await getToken();
  const headers = new Headers(init.headers);

  headers.set("Accept", accept);

  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  } else if (!isLocalDemoAuthEnabled()) {
    throw new APIClientError("Authentication token is unavailable.", 401);
  }

  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  return headers;
}

async function parseEnvelope<T>(response: Response) {
  const text = await response.text();
  if (!text) {
    return {
      data: null,
      error: response.ok ? null : response.statusText,
      meta: {}
    } satisfies APIResponse<T>;
  }

  const parsed: unknown = JSON.parse(text);
  if (parsed && typeof parsed === "object" && !("data" in parsed) && "detail" in parsed) {
    const detail = (parsed as { detail?: unknown }).detail;
    let error = response.statusText;

    if (typeof detail === "string") {
      error = detail;
    } else if (Array.isArray(detail)) {
      error = detail
        .map((item) => {
          if (typeof item === "string") {
            return item;
          }

          if (item && typeof item === "object" && "msg" in item && typeof item.msg === "string") {
            return item.msg;
          }

          return JSON.stringify(item);
        })
        .join("; ");
    }

    return {
      data: null,
      error,
      meta: {}
    } satisfies APIResponse<T>;
  }

  return parsed as APIResponse<T>;
}

async function requestEnvelope<T, M = Record<string, unknown>>(
  path: string,
  init: RequestInit,
  getToken: TokenGetter
): Promise<{ data: T; meta: M }> {
  const headers = await buildAuthHeaders(init, getToken, "application/json");

  const response = await fetch(buildApiUrl(path), {
    ...init,
    cache: "no-store",
    headers
  });

  const envelope = (await parseEnvelope<T>(response)) as APIResponseWithMeta<T, M>;
  if (!response.ok || envelope.error) {
    throw new APIClientError(
      envelope.error || response.statusText || "Request failed.",
      response.status,
      (envelope.meta ?? {}) as Record<string, unknown>
    );
  }

  if (envelope.data === null) {
    throw new APIClientError("API returned no data.", response.status, (envelope.meta ?? {}) as Record<string, unknown>);
  }

  return {
    data: envelope.data,
    meta: envelope.meta
  };
}

async function request<T>(
  path: string,
  init: RequestInit,
  getToken: TokenGetter
): Promise<T> {
  const envelope = await requestEnvelope<T>(path, init, getToken);
  return envelope.data;
}

async function requestBinary(
  path: string,
  init: RequestInit,
  getToken: TokenGetter
): Promise<Blob> {
  const headers = await buildAuthHeaders(init, getToken, "application/pdf");

  const response = await fetch(buildApiUrl(path), {
    ...init,
    cache: "no-store",
    headers
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new APIClientError(errorText || response.statusText || "Request failed.", response.status);
  }

  return response.blob();
}

function buildResultsPath(
  runId: string,
  options?: {
    criticalOnly?: boolean;
    page?: number;
    pageSize?: number;
  }
) {
  if (options?.criticalOnly) {
    return `/api/v1/attack-runs/${runId}/results/critical`;
  }

  const query = new URLSearchParams();
  if (options?.page) {
    query.set("page", String(options.page));
  }
  if (options?.pageSize) {
    query.set("page_size", String(options.pageSize));
  }

  const suffix = query.size > 0 ? `?${query.toString()}` : "";
  return `/api/v1/attack-runs/${runId}/results${suffix}`;
}

export function createApiClient(getToken: TokenGetter) {
  async function getRunResultsPage(
    runId: string,
    options?: {
      criticalOnly?: boolean;
      page?: number;
      pageSize?: number;
    }
  ) {
    const envelope = await requestEnvelope<AttackResultResponse[], PaginationMeta>(
      buildResultsPath(runId, options),
      { method: "GET" },
      getToken
    );

    return {
      results: envelope.data,
      pagination: envelope.meta
    };
  }

  async function getAllRunResults(runId: string) {
    let currentPage = 1;
    let pagination: PaginationMeta = {
      page: 1,
      page_size: 100,
      total: 0,
      total_pages: 0
    };
    const allResults: AttackResultResponse[] = [];

    do {
      const pageResponse = await getRunResultsPage(runId, { page: currentPage, pageSize: 100 });
      allResults.push(...pageResponse.results);
      pagination = pageResponse.pagination;
      currentPage += 1;
    } while (pagination.total_pages > 0 && currentPage <= pagination.total_pages);

    return {
      results: allResults,
      pagination
    };
  }

  return {
    async getAttackRuns() {
      return request<AttackRunResponse[]>("/api/v1/attack-runs/", { method: "GET" }, getToken);
    },
    async getAttackRunsSummary() {
      return request<AttackRunsSummaryResponse>("/api/v1/attack-runs/summary", { method: "GET" }, getToken);
    },
    async createAttackRun(payload: CreateAttackRunRequest) {
      return request<AttackRunResponse>(
        "/api/v1/attack-runs/",
        {
          method: "POST",
          body: JSON.stringify(payload)
        },
        getToken
      );
    },
    async getAttackRun(runId: string) {
      return request<AttackRunResponse>(`/api/v1/attack-runs/${runId}`, { method: "GET" }, getToken);
    },
    async downloadAttackRunReport(runId: string) {
      return requestBinary(`/api/v1/attack-runs/${runId}/report`, { method: "GET" }, getToken);
    },
    async getAttackRunDetail(runId: string) {
      const envelope = await requestEnvelope<AttackRunResponse, AttackRunSummaryMeta>(
        `/api/v1/attack-runs/${runId}`,
        { method: "GET" },
        getToken
      );

      return {
        run: envelope.data,
        summary: envelope.meta
      };
    },
    async getRunResults(
      runId: string,
      options?: {
        criticalOnly?: boolean;
        page?: number;
        pageSize?: number;
      }
    ) {
      return request<AttackResultResponse[]>(buildResultsPath(runId, options), { method: "GET" }, getToken);
    },
    getRunResultsPage,
    getAllRunResults,
    async getTargetSystems() {
      return request<TargetSystemResponse[]>("/api/v1/target-systems", { method: "GET" }, getToken);
    },
    async createTargetSystem(payload: CreateTargetSystemRequest) {
      return request<TargetSystemResponse>(
        "/api/v1/target-systems",
        {
          method: "POST",
          body: JSON.stringify(payload)
        },
        getToken
      );
    },
    async getLlmRoleSettings() {
      return request<LLMRoleSettingResponse[]>("/api/v1/llm-role-settings", { method: "GET" }, getToken);
    },
    async updateLlmRoleSetting(role: LLMRole, payload: UpdateLLMRoleSettingRequest) {
      return request<LLMRoleSettingResponse>(
        `/api/v1/llm-role-settings/${role}`,
        {
          method: "PUT",
          body: JSON.stringify(payload)
        },
        getToken
      );
    },
    async testLlmRoleSetting(role: LLMRole) {
      return request<LLMConnectionTestResponse>(
        `/api/v1/llm-role-settings/${role}/test`,
        { method: "POST" },
        getToken
      );
    },
    async getTargetRiskTrend(targetSystemId: string) {
      return request<TargetRiskTrendPoint[]>(
        `/api/v1/analytics/target/${targetSystemId}/trend`,
        { method: "GET" },
        getToken
      );
    },
    async getTargetAttackSurface(targetSystemId: string) {
      return request<AttackSurfaceSummaryItem[]>(
        `/api/v1/analytics/target/${targetSystemId}/attack-surface`,
        { method: "GET" },
        getToken
      );
    }
  };
}

export function useApiClient() {
  const { getToken } = useAppAuth();

  return useMemo(() => createApiClient(getToken), [getToken]);
}
