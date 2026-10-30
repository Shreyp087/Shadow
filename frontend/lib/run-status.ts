import type { AttackRunStatus } from "@/types/api";

export function isActiveRun(status?: AttackRunStatus): boolean {
  return status === "PENDING" || status === "RUNNING";
}
