export type LedgerVisibility = "private" | "team" | "auditor";

export interface LedgerEntry {
  id: string;
  reference: string;
  amount: number;
  currency: string;
  description: string;
  visibility: LedgerVisibility;
  createdAt: string;
}

export interface ApiEnvelope<T> {
  data: T;
  message?: string;
}
