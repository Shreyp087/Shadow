export type UUID = string;
export type ISODateTimeString = string;
export type DecimalString = string;

export type AttackRunStatus = "PENDING" | "RUNNING" | "COMPLETED" | "FAILED";
export type TargetSystemType = "openai_compatible" | "anthropic";
export type AttackVectorCategory =
  | "PROMPT_INJECTION"
  | "JAILBREAK"
  | "DATA_EXTRACTION"
  | "ROLE_CONFUSION"
  | "INDIRECT_INJECTION";
export type SeverityLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type RiskCategory = "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type AttackSurfaceTrend = "IMPROVING" | "WORSENING" | "STABLE";

export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | {
      [key: string]: JsonValue;
    };

export interface APIResponse<T> {
  data: T | null;
  error: string | null;
  meta: Record<string, unknown>;
}

export interface APIResponseWithMeta<T, M> {
  data: T | null;
  error: string | null;
  meta: M;
}

export interface UserResponse {
  id: UUID;
  clerk_user_id: string;
  email: string;
  created_at: ISODateTimeString;
}

export interface CreateTargetSystemRequest {
  name: string;
  description: string | null;
  api_endpoint: string;
  target_type: TargetSystemType;
  api_key: string;
  model_name: string;
  is_active: boolean;
}

export interface TargetSystemResponse {
  id: UUID;
  user_id: UUID;
  name: string;
  description: string | null;
  api_endpoint: string;
  target_type: TargetSystemType;
  api_key_masked: string;
  model_name: string;
  created_at: ISODateTimeString;
  is_active: boolean;
}

export interface CreateAttackRunRequest {
  target_system_id: UUID;
  vector_category_filter?: string[] | null;
}

export interface AttackRunsSummaryResponse {
  total_scans: number;
  vulnerabilities_found: number;
  critical_findings: number;
  avg_risk_score: DecimalString | null;
}

export interface AttackRunResponse {
  id: UUID;
  target_system_id: UUID;
  user_id: UUID;
  status: AttackRunStatus;
  started_at: ISODateTimeString | null;
  completed_at: ISODateTimeString | null;
  total_attacks: number;
  vulnerabilities_found: number;
  risk_score_avg: DecimalString | null;
}

export interface AttackRunSummaryMeta {
  total_results: number;
  critical_or_high_results: number;
  risk_breakdown: Partial<Record<RiskCategory, number>>;
}

export interface AttackVectorResponse {
  id: UUID;
  name: string;
  category: AttackVectorCategory;
  prompt_template: string;
  severity: SeverityLevel;
  is_active: boolean;
}

export interface AttackResultResponse {
  id: UUID;
  attack_run_id: UUID;
  attack_vector_id: UUID;
  attack_category?: AttackVectorCategory | null;
  prompt_sent: string;
  response_received: string;
  risk_score: number;
  is_mutation: boolean;
  risk_category: RiskCategory;
  risk_reason: string;
  executed_at: ISODateTimeString;
  trust_ledger_entry_hash?: string | null;
}

export interface PaginationMeta {
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
}

export interface TrustLedgerEntryResponse {
  id: UUID;
  attack_result_id: UUID;
  entry_hash: string;
  prev_hash: string | null;
  payload_json: Record<string, JsonValue>;
  created_at: ISODateTimeString;
}

export interface TargetRiskTrendPoint {
  date: string;
  avg_risk_score: number;
  total_attacks: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
}

export interface AttackSurfaceSummaryItem {
  category: AttackVectorCategory;
  worst_risk: RiskCategory;
  total_attacks: number;
  high_critical_count: number;
  trend: AttackSurfaceTrend;
}
