"use client";

import { AlertOctagon, ShieldAlert, Sigma, Swords } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { type FormEvent, useMemo, useState, useTransition } from "react";
import useSWR from "swr";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger
} from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useApiClient } from "@/lib/api-client";
import type {
  AttackRunResponse,
  AttackRunsSummaryResponse,
  CreateAttackRunRequest,
  RiskCategory
} from "@/types/api";

const statusBadgeVariants: Record<AttackRunResponse["status"], "slate" | "blue" | "green" | "red"> = {
  PENDING: "slate",
  RUNNING: "blue",
  COMPLETED: "green",
  FAILED: "red"
};

const riskBadgeVariants: Record<RiskCategory, "green" | "blue" | "yellow" | "orange" | "red"> = {
  SAFE: "green",
  LOW: "blue",
  MEDIUM: "yellow",
  HIGH: "orange",
  CRITICAL: "red"
};

export default function DashboardPage() {
  const apiClient = useApiClient();
  const router = useRouter();
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [selectedTargetSystemId, setSelectedTargetSystemId] = useState("");
  const [createError, setCreateError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  const {
    data: attackRuns = [],
    error: attackRunsError,
    isLoading: attackRunsLoading,
    mutate: mutateAttackRuns
  } = useSWR("attack-runs", () => apiClient.getAttackRuns(), {
    refreshInterval: (currentData: AttackRunResponse[] | undefined) =>
      currentData?.some((run) => run.status === "RUNNING") ? 5000 : 0
  });

  const hasRunningRun = attackRuns.some((run) => run.status === "RUNNING");

  const {
    data: summary,
    error: summaryError,
    isLoading: summaryLoading,
    mutate: mutateSummary
  } = useSWR("attack-runs-summary", () => apiClient.getAttackRunsSummary(), {
    refreshInterval: hasRunningRun ? 5000 : 0
  });

  const {
    data: targetSystems = [],
    error: targetSystemsError,
    isLoading: targetSystemsLoading
  } = useSWR("target-systems", () => apiClient.getTargetSystems());

  const targetSystemNameById = useMemo(
    () => new Map(targetSystems.map((system) => [system.id, system.name])),
    [targetSystems]
  );
  const activeTargetSystemCount = useMemo(
    () => targetSystems.filter((system) => system.is_active).length,
    [targetSystems]
  );

  const metrics = buildMetrics(summary, summaryLoading);
  const runsErrorMessage = attackRunsError instanceof Error ? attackRunsError.message : null;
  const summaryErrorMessage = summaryError instanceof Error ? summaryError.message : null;
  const systemsErrorMessage = targetSystemsError instanceof Error ? targetSystemsError.message : null;

  function handleCreateRun(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setCreateError(null);

    if (!selectedTargetSystemId) {
      setCreateError("Select a target system before starting a scan.");
      return;
    }

    startTransition(async () => {
      try {
        const payload: CreateAttackRunRequest = {
          target_system_id: selectedTargetSystemId,
          vector_category_filter: null
        };
        const attackRun = await apiClient.createAttackRun(payload);
        await Promise.all([mutateAttackRuns(), mutateSummary()]);
        setIsDialogOpen(false);
        setSelectedTargetSystemId("");
        router.push(`/dashboard/runs/${attackRun.id}`);
      } catch (requestError) {
        setCreateError(requestError instanceof Error ? requestError.message : "Unable to start a new scan.");
      }
    });
  }

  return (
    <div className="space-y-8">
      <section className="flex flex-col gap-4 rounded-[2rem] border bg-slate-950 px-6 py-8 text-white shadow-[0_30px_90px_rgba(15,23,42,0.18)] lg:flex-row lg:items-end lg:justify-between lg:px-8">
        <div className="max-w-3xl">
          <p className="text-xs uppercase tracking-[0.28em] text-teal-200/70">Operational overview</p>
          <h2 className="mt-3 font-[family-name:var(--font-heading)] text-4xl font-semibold leading-tight">
            Monitor recent attack runs, spot active risk, and launch the next scan in one place.
          </h2>
          <p className="mt-4 text-sm leading-7 text-slate-300">
            The dashboard polls the backend every five seconds while a run is still executing, so critical changes
            surface without a manual refresh loop.
          </p>
          <p className="mt-2 text-xs leading-6 text-teal-100/80">
            Dashboard data and scan actions use the authenticated API client, which supplies your Clerk bearer token
            whenever Clerk authentication is enabled.
          </p>
        </div>

        <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogTrigger asChild>
            <Button size="lg" className="min-w-[180px]">
              New Scan
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Start a new attack run</DialogTitle>
              <DialogDescription>
                Choose one registered target system and ShadowLedger will queue every active attack vector in the
                background. This sends provider requests and may incur usage charges.
              </DialogDescription>
            </DialogHeader>

            <form onSubmit={handleCreateRun} className="space-y-4">
              <div className="space-y-2">
                <label htmlFor="target-system-select" className="text-sm font-medium">
                  Target system
                </label>
                <select
                  id="target-system-select"
                  value={selectedTargetSystemId}
                  onChange={(event) => setSelectedTargetSystemId(event.target.value)}
                  className="h-12 w-full rounded-2xl border bg-background px-4 text-sm outline-none transition focus:border-primary"
                  disabled={targetSystemsLoading || activeTargetSystemCount === 0}
                >
                  <option value="">
                    {targetSystemsLoading ? "Loading target systems..." : "Select a target system"}
                  </option>
                  {targetSystems.map((system) => (
                    <option key={system.id} value={system.id} disabled={!system.is_active}>
                      {system.name} - {system.model_name}{system.is_active ? "" : " (inactive)"}
                    </option>
                  ))}
                </select>
              </div>

              {systemsErrorMessage ? <p className="text-sm text-orange-600">{systemsErrorMessage}</p> : null}
              {!targetSystemsLoading && activeTargetSystemCount === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No active, executable target systems are available. Add an authorized target in{" "}
                  <Link href="/dashboard/systems" className="font-medium text-primary underline underline-offset-4">
                    Target Systems
                  </Link>
                  .
                </p>
              ) : null}
              {createError ? <p className="text-sm text-orange-600">{createError}</p> : null}

              <DialogFooter>
                <DialogClose asChild>
                  <Button type="button" variant="outline">
                    Cancel
                  </Button>
                </DialogClose>
                <Button type="submit" disabled={isPending || activeTargetSystemCount === 0}>
                  {isPending ? "Starting..." : "Start attack run"}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </section>

      <section className="grid gap-4 md:grid-cols-2 2xl:grid-cols-4">
        {metrics.map(({ title, value, description, icon: Icon, badge }) => (
          <Card key={title} className="min-w-0">
            <CardHeader className="flex flex-row items-start justify-between gap-4 space-y-0 pb-3">
              <div className="min-w-0 flex-1">
                <CardDescription className="text-xs uppercase tracking-[0.22em]">{title}</CardDescription>
                <CardTitle className="mt-3 break-words text-[clamp(2.1rem,4vw,3rem)] leading-tight">{value}</CardTitle>
              </div>
              <div className="shrink-0 rounded-2xl bg-secondary p-3 text-secondary-foreground">
                <Icon className="h-5 w-5" />
              </div>
            </CardHeader>
            <CardContent className="flex flex-col items-start gap-3 sm:flex-row sm:items-center sm:justify-between">
              <p className="max-w-[28ch] text-sm leading-7 text-muted-foreground">{description}</p>
              {badge ? <Badge variant={badge.variant}>{badge.label}</Badge> : null}
            </CardContent>
          </Card>
        ))}
      </section>

      {summaryErrorMessage || runsErrorMessage ? (
        <Card className="border-orange-200 bg-orange-50/90">
          <CardContent className="p-5 text-sm text-orange-900">
            {summaryErrorMessage || runsErrorMessage}
          </CardContent>
        </Card>
      ) : null}

      <Card className="min-w-0 overflow-hidden">
        <CardHeader className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <CardTitle>Recent Attack Runs</CardTitle>
            <CardDescription>
              The latest scans across your registered target systems, with live polling while anything is running.
            </CardDescription>
          </div>
          {hasRunningRun ? <Badge variant="blue">Polling every 5s</Badge> : null}
        </CardHeader>
        <CardContent>
          <Table className="min-w-[860px]">
            <TableHeader>
              <TableRow>
                <TableHead>Target System</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Total Attacks</TableHead>
                <TableHead>Vulnerabilities</TableHead>
                <TableHead>Avg Risk</TableHead>
                <TableHead>Started At</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {attackRunsLoading ? (
                Array.from({ length: 4 }).map((_, index) => (
                  <TableRow key={`loading-${index}`}>
                    <TableCell colSpan={7}>
                      <div className="h-10 animate-pulse rounded-2xl bg-muted/60" />
                    </TableCell>
                  </TableRow>
                ))
              ) : attackRuns.length > 0 ? (
                attackRuns.map((run) => {
                  const riskCategory = deriveRiskCategory(run.risk_score_avg);
                  const targetSystemName =
                    targetSystemNameById.get(run.target_system_id) ?? `System ${shortenIdentifier(run.target_system_id)}`;

                  return (
                    <TableRow key={run.id}>
                      <TableCell>
                        <div>
                          <p className="font-medium">{targetSystemName}</p>
                          <p className="mt-1 text-xs text-muted-foreground">{shortenIdentifier(run.target_system_id)}</p>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant={statusBadgeVariants[run.status]}>{run.status}</Badge>
                      </TableCell>
                      <TableCell>{run.total_attacks}</TableCell>
                      <TableCell>{run.vulnerabilities_found}</TableCell>
                      <TableCell>
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-medium">{formatRiskScore(run.risk_score_avg) ?? "Pending"}</span>
                          {run.risk_score_avg ? (
                            <Badge variant={riskBadgeVariants[riskCategory]}>{riskCategory}</Badge>
                          ) : null}
                        </div>
                      </TableCell>
                      <TableCell>{formatDateTime(run.started_at)}</TableCell>
                      <TableCell className="text-right">
                        <Button asChild size="sm" variant="outline">
                          <Link href={`/dashboard/runs/${run.id}`}>View</Link>
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })
              ) : (
                <TableRow>
                  <TableCell colSpan={7} className="py-10 text-center text-sm text-muted-foreground">
                    No attack runs yet. Start your first scan to populate this table.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

function buildMetrics(
  summary: AttackRunsSummaryResponse | undefined,
  isLoading: boolean
) {
  const avgRiskValue = summary?.avg_risk_score ?? null;
  const avgRiskCategory = deriveRiskCategory(avgRiskValue);

  return [
    {
      title: "Total Scans",
      value: isLoading ? "..." : String(summary?.total_scans ?? 0),
      description: "All attack runs recorded by the backend.",
      icon: Swords,
      badge: null
    },
    {
      title: "Vulnerabilities Found",
      value: isLoading ? "..." : String(summary?.vulnerabilities_found ?? 0),
      description: "Runs that surfaced high or critical issues.",
      icon: ShieldAlert,
      badge: null
    },
    {
      title: "Critical Findings",
      value: isLoading ? "..." : String(summary?.critical_findings ?? 0),
      description: "The highest-severity results needing immediate review.",
      icon: AlertOctagon,
      badge: {
        label: "critical",
        variant: "red" as const
      }
    },
    {
      title: "Avg Risk Score",
      value: isLoading ? "..." : formatRiskScore(avgRiskValue) ?? "Pending",
      description: "Rolling average across all completed scan activity.",
      icon: Sigma,
      badge: avgRiskValue
        ? {
            label: avgRiskCategory,
            variant: riskBadgeVariants[avgRiskCategory]
          }
        : {
            label: "no data",
            variant: "slate" as const
          }
    }
  ] as const;
}

function deriveRiskCategory(score: string | null): RiskCategory {
  const numericScore = Number(score ?? 0);

  if (numericScore <= 19) {
    return "SAFE";
  }
  if (numericScore <= 39) {
    return "LOW";
  }
  if (numericScore <= 59) {
    return "MEDIUM";
  }
  if (numericScore <= 79) {
    return "HIGH";
  }
  return "CRITICAL";
}

function formatDateTime(value: string | null) {
  if (!value) {
    return "Not started";
  }

  return new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(value));
}

function formatRiskScore(value: string | null) {
  if (!value) {
    return null;
  }

  const numericScore = Number(value);
  if (Number.isNaN(numericScore)) {
    return value;
  }

  return numericScore.toFixed(2);
}

function shortenIdentifier(value: string) {
  if (value.length <= 12) {
    return value;
  }

  return `${value.slice(0, 8)}...${value.slice(-4)}`;
}
