"use client";

import { AlertTriangle, BarChart3, Clock3, Download, Fingerprint, ShieldAlert } from "lucide-react";
import { useParams } from "next/navigation";
import { useMemo, useState } from "react";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import useSWR from "swr";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle
} from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useApiClient } from "@/lib/api-client";
import { cn } from "@/lib/utils";
import type {
  AttackResultResponse,
  AttackRunResponse,
  AttackRunSummaryMeta,
  RiskCategory,
  TargetRiskTrendPoint
} from "@/types/api";

type FilterOption = "ALL" | RiskCategory;

const pageSize = 10;

const runBadgeVariants: Record<AttackRunResponse["status"], "slate" | "blue" | "green" | "red"> = {
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

const distributionToneClasses: Record<RiskCategory, string> = {
  SAFE: "bg-emerald-500",
  LOW: "bg-sky-500",
  MEDIUM: "bg-amber-400",
  HIGH: "bg-orange-500",
  CRITICAL: "bg-rose-500"
};

const riskScoreToneClasses: Record<RiskCategory, string> = {
  SAFE: "text-emerald-700",
  LOW: "text-sky-700",
  MEDIUM: "text-amber-700",
  HIGH: "text-orange-700",
  CRITICAL: "text-rose-700"
};

const orderedRiskCategories: RiskCategory[] = ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const filterOptions: FilterOption[] = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"];

export default function RunDetailPage() {
  const { runId } = useParams<{ runId: string }>();
  const apiClient = useApiClient();
  const [activeFilter, setActiveFilter] = useState<FilterOption>("ALL");
  const [currentPage, setCurrentPage] = useState(1);
  const [selectedResult, setSelectedResult] = useState<AttackResultResponse | null>(null);
  const [isDownloadingReport, setIsDownloadingReport] = useState(false);
  const [reportDownloadError, setReportDownloadError] = useState<string | null>(null);

  const {
    data: runDetail,
    error: runDetailError,
    isLoading: runDetailLoading
  } = useSWR(["attack-run-detail", runId], () => apiClient.getAttackRunDetail(runId), {
    refreshInterval: (currentData) => (currentData?.run.status === "RUNNING" ? 3000 : 0)
  });

  const {
    data: runResultsData,
    error: runResultsError,
    isLoading: runResultsLoading
  } = useSWR(["attack-run-results", runId], () => apiClient.getAllRunResults(runId), {
    refreshInterval: runDetail?.run.status === "RUNNING" ? 3000 : 0
  });

  const {
    data: targetSystems = [],
    error: targetSystemsError
  } = useSWR("target-systems", () => apiClient.getTargetSystems());

  const run = runDetail?.run ?? null;
  const summary = runDetail?.summary;
  const allResults = useMemo(() => runResultsData?.results ?? [], [runResultsData?.results]);
  const targetSystemId = run?.target_system_id ?? null;

  const {
    data: riskTrend = [],
    error: riskTrendError,
    isLoading: riskTrendLoading
  } = useSWR(
    targetSystemId ? ["target-risk-trend", targetSystemId] : null,
    () => apiClient.getTargetRiskTrend(targetSystemId as string),
    {
      refreshInterval: run?.status === "RUNNING" ? 3000 : 0
    }
  );

  const targetSystemNameById = useMemo(
    () => new Map(targetSystems.map((system) => [system.id, system.name])),
    [targetSystems]
  );
  const targetSystemName = run ? targetSystemNameById.get(run.target_system_id) ?? `System ${shortenIdentifier(run.target_system_id)}` : "Loading...";

  const riskBreakdown = useMemo(
    () => normalizeRiskBreakdown(summary, allResults),
    [allResults, summary]
  );
  const totalDistributionResults = orderedRiskCategories.reduce((total, category) => total + riskBreakdown[category], 0);

  const filteredResults = useMemo(() => {
    if (activeFilter === "ALL") {
      return allResults;
    }

    return allResults.filter((result) => result.risk_category === activeFilter);
  }, [activeFilter, allResults]);

  const totalPages = Math.max(1, Math.ceil(filteredResults.length / pageSize));
  const safeCurrentPage = Math.min(currentPage, totalPages);
  const paginatedResults = filteredResults.slice((safeCurrentPage - 1) * pageSize, safeCurrentPage * pageSize);
  const recentTrendAverage = useMemo(() => {
    if (riskTrend.length === 0) {
      return null;
    }

    const trailingWindow = riskTrend.slice(-7);
    const total = trailingWindow.reduce((sum, point) => sum + point.avg_risk_score, 0);
    return (total / trailingWindow.length).toFixed(1);
  }, [riskTrend]);
  const trendPeak = useMemo(() => {
    if (riskTrend.length === 0) {
      return 0;
    }

    return Math.max(...riskTrend.map((point) => point.avg_risk_score));
  }, [riskTrend]);
  const trendCriticalCount = useMemo(
    () => riskTrend.reduce((sum, point) => sum + point.critical_count, 0),
    [riskTrend]
  );

  const errorMessage =
    (runDetailError instanceof Error && runDetailError.message) ||
    (runResultsError instanceof Error && runResultsError.message) ||
    (riskTrendError instanceof Error && riskTrendError.message) ||
    reportDownloadError ||
    (targetSystemsError instanceof Error && targetSystemsError.message) ||
    null;

  function handleFilterChange(filter: FilterOption) {
    setActiveFilter(filter);
    setCurrentPage(1);
  }

  async function handleDownloadReport() {
    if (!run) {
      return;
    }

    setReportDownloadError(null);
    setIsDownloadingReport(true);

    try {
      const reportBlob = await apiClient.downloadAttackRunReport(run.id);
      const objectUrl = window.URL.createObjectURL(reportBlob);
      const anchor = document.createElement("a");
      anchor.href = objectUrl;
      anchor.download = `shadowledger-attack-run-${run.id}.pdf`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.URL.revokeObjectURL(objectUrl);
    } catch (error) {
      setReportDownloadError(error instanceof Error ? error.message : "Failed to download the audit report.");
    } finally {
      setIsDownloadingReport(false);
    }
  }

  return (
    <div className="space-y-6">
      <Card className="overflow-hidden border-slate-200 bg-slate-950 text-white shadow-[0_30px_90px_rgba(15,23,42,0.16)]">
        <CardHeader className="border-b border-white/10 pb-6">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <CardDescription className="text-xs uppercase tracking-[0.28em] text-teal-200/70">
                Attack run detail
              </CardDescription>
              <CardTitle className="mt-3 text-4xl text-white">Run {runId}</CardTitle>
              <p className="mt-4 max-w-2xl text-sm leading-7 text-slate-300">
                Inspect run state, risk distribution, and full result evidence while ShadowLedger continues polling
                active executions every three seconds.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="border-white/20 bg-white/5 text-white hover:bg-white/10 hover:text-white"
                onClick={handleDownloadReport}
                disabled={!run || isDownloadingReport}
              >
                <Download className="mr-2 h-4 w-4" />
                {isDownloadingReport ? "Preparing Report..." : "Download Report"}
              </Button>
              {run ? <Badge variant={runBadgeVariants[run.status]}>{run.status}</Badge> : null}
            </div>
          </div>
        </CardHeader>
        <CardContent className="pt-6">
          {runDetailLoading ? (
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
              {Array.from({ length: 6 }).map((_, index) => (
                <div key={index} className="h-24 animate-pulse rounded-[1.25rem] bg-white/10" />
              ))}
            </div>
          ) : run ? (
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
              <SummaryItem label="Target system" value={targetSystemName} />
              <SummaryItem label="Started at" value={formatDateTime(run.started_at)} />
              <SummaryItem label="Completed at" value={formatDateTime(run.completed_at)} />
              <SummaryItem label="Total attacks" value={String(run.total_attacks)} />
              <SummaryItem label="Vulnerabilities" value={String(run.vulnerabilities_found)} />
              <SummaryItem label="Avg risk score" value={run.risk_score_avg ?? "Pending"} />
            </div>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <CardDescription className="text-xs uppercase tracking-[0.24em]">Trend line</CardDescription>
              <CardTitle className="mt-3">Avg risk score over time</CardTitle>
            </div>
            <div className="grid gap-3 sm:grid-cols-3">
              <TrendStat label="7-day avg" value={recentTrendAverage ? `${recentTrendAverage}` : "0.0"} />
              <TrendStat label="30-day peak" value={trendPeak.toFixed(1)} />
              <TrendStat label="Critical hits" value={String(trendCriticalCount)} />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {riskTrendLoading && !riskTrend.length ? (
            <div className="h-[18rem] animate-pulse rounded-[1.5rem] bg-muted/60" />
          ) : (
            <div className="h-[18rem] rounded-[1.5rem] border bg-gradient-to-br from-slate-50 via-white to-teal-50 p-4">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={riskTrend} margin={{ top: 16, right: 16, bottom: 8, left: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#cbd5e1" vertical={false} />
                  <XAxis
                    dataKey="date"
                    tickLine={false}
                    axisLine={false}
                    tickMargin={10}
                    minTickGap={24}
                    tickFormatter={formatChartDate}
                  />
                  <YAxis
                    domain={[0, 100]}
                    tickLine={false}
                    axisLine={false}
                    tickMargin={10}
                    width={36}
                  />
                  <Tooltip
                    cursor={{ stroke: "#0f766e", strokeDasharray: "4 4" }}
                    contentStyle={{
                      borderRadius: "16px",
                      border: "1px solid #cbd5e1",
                      backgroundColor: "#ffffff"
                    }}
                    content={<TrendTooltip />}
                  />
                  <Line
                    type="monotone"
                    dataKey="avg_risk_score"
                    stroke="#0f766e"
                    strokeWidth={3}
                    dot={{ r: 0 }}
                    activeDot={{ r: 5, fill: "#0f766e", stroke: "#ffffff", strokeWidth: 2 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <CardDescription className="text-xs uppercase tracking-[0.24em]">Risk distribution</CardDescription>
              <CardTitle className="mt-3">Result severity mix</CardTitle>
            </div>
            <div className="inline-flex items-center gap-2 rounded-full bg-secondary px-4 py-2 text-xs uppercase tracking-[0.2em] text-secondary-foreground">
              <BarChart3 className="h-4 w-4" />
              {totalDistributionResults} results
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="flex h-8 overflow-hidden rounded-full bg-muted">
            {orderedRiskCategories.map((category) => {
              const count = riskBreakdown[category];
              const width = totalDistributionResults > 0 ? (count / totalDistributionResults) * 100 : 0;

              if (count === 0) {
                return null;
              }

              return (
                <div
                  key={category}
                  className={cn(
                    "flex min-w-[4rem] items-center justify-center px-3 text-[11px] font-medium uppercase tracking-[0.16em] text-white",
                    distributionToneClasses[category]
                  )}
                  style={{ width: `${width}%` }}
                  title={`${category}: ${count}`}
                >
                  {category} {count}
                </div>
              );
            })}
          </div>

          <div className="grid gap-3 md:grid-cols-5">
            {orderedRiskCategories.map((category) => (
              <div key={category} className="rounded-[1.25rem] bg-muted/50 p-4">
                <div className="flex items-center gap-2">
                  <span className={cn("h-3 w-3 rounded-full", distributionToneClasses[category])} />
                  <p className="text-xs uppercase tracking-[0.2em] text-muted-foreground">{category}</p>
                </div>
                <p className="mt-3 font-[family-name:var(--font-heading)] text-2xl font-semibold">
                  {riskBreakdown[category]}
                </p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {errorMessage ? (
        <Card className="border-orange-200 bg-orange-50/90">
          <CardContent className="p-5 text-sm text-orange-900">{errorMessage}</CardContent>
        </Card>
      ) : null}

      <Card>
        <CardHeader className="gap-4">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
            <div>
              <CardDescription className="text-xs uppercase tracking-[0.24em]">Run results</CardDescription>
              <CardTitle className="mt-3">Detailed findings</CardTitle>
            </div>
            {run?.status === "RUNNING" ? <Badge variant="blue">Polling every 3s</Badge> : null}
          </div>

          <div className="flex flex-wrap gap-2">
            {filterOptions.map((filter) => {
              const active = filter === activeFilter;

              return (
                <Button
                  key={filter}
                  type="button"
                  variant={active ? "default" : "outline"}
                  size="sm"
                  onClick={() => handleFilterChange(filter)}
                >
                  {filter === "ALL" ? "All" : toTitleCase(filter)}
                </Button>
              );
            })}
          </div>
        </CardHeader>
        <CardContent className="space-y-5">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Attack Category</TableHead>
                <TableHead>Prompt Sent</TableHead>
                <TableHead>Risk Score</TableHead>
                <TableHead>Risk Category</TableHead>
                <TableHead>Risk Reason</TableHead>
                <TableHead>Executed At</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {runResultsLoading ? (
                Array.from({ length: 6 }).map((_, index) => (
                  <TableRow key={`loading-${index}`}>
                    <TableCell colSpan={6}>
                      <div className="h-10 animate-pulse rounded-2xl bg-muted/60" />
                    </TableCell>
                  </TableRow>
                ))
              ) : paginatedResults.length > 0 ? (
                paginatedResults.map((result) => {
                  const scoreCategory = deriveRiskCategory(result.risk_score);

                  return (
                    <TableRow
                      key={result.id}
                      className="cursor-pointer"
                      onClick={() => setSelectedResult(result)}
                    >
                      <TableCell>
                        <Badge variant="secondary">
                          {result.attack_category ? toTitleCase(result.attack_category) : "Unresolved"}
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-[22rem]">
                        <span className="block truncate font-medium text-foreground">
                          {truncateText(result.prompt_sent, 80)}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className={cn("font-semibold", riskScoreToneClasses[scoreCategory])}>
                          {result.risk_score}
                        </span>
                      </TableCell>
                      <TableCell>
                        <Badge variant={riskBadgeVariants[result.risk_category]}>{result.risk_category}</Badge>
                      </TableCell>
                      <TableCell className="max-w-[18rem] text-muted-foreground">
                        {truncateText(result.risk_reason, 90)}
                      </TableCell>
                      <TableCell>{formatDateTime(result.executed_at)}</TableCell>
                    </TableRow>
                  );
                })
              ) : (
                <TableRow>
                  <TableCell colSpan={6} className="py-10 text-center text-sm text-muted-foreground">
                    No results match the current filter.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>

          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <p className="text-sm text-muted-foreground">
              Showing {filteredResults.length === 0 ? 0 : (safeCurrentPage - 1) * pageSize + 1}-
              {Math.min(safeCurrentPage * pageSize, filteredResults.length)} of {filteredResults.length} filtered results
            </p>
            <div className="flex items-center gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setCurrentPage((page) => Math.max(1, page - 1))}
                disabled={safeCurrentPage === 1}
              >
                Previous
              </Button>
              <span className="min-w-[5rem] text-center text-sm text-muted-foreground">
                Page {safeCurrentPage} / {totalPages}
              </span>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setCurrentPage((page) => Math.min(totalPages, page + 1))}
                disabled={safeCurrentPage === totalPages}
              >
                Next
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      <Sheet open={selectedResult !== null} onOpenChange={(open) => !open && setSelectedResult(null)}>
        <SheetContent side="right" className="flex flex-col gap-6 overflow-y-auto">
          <SheetHeader>
            <SheetTitle>Attack result inspection</SheetTitle>
            <SheetDescription>
              Full prompt, model response, and risk context for the selected result entry.
            </SheetDescription>
          </SheetHeader>

          {selectedResult ? (
            <div className="space-y-6">
              <div className="flex flex-wrap items-center gap-3">
                <Badge variant={riskBadgeVariants[selectedResult.risk_category]}>{selectedResult.risk_category}</Badge>
                <span className={cn("text-lg font-semibold", riskScoreToneClasses[deriveRiskCategory(selectedResult.risk_score)])}>
                  Score {selectedResult.risk_score}
                </span>
              </div>

              <DetailBlock
                icon={ShieldAlert}
                label="Risk assessment"
                value={selectedResult.risk_reason || "No risk reason recorded."}
              />
              <DetailBlock
                icon={AlertTriangle}
                label="Prompt sent"
                value={selectedResult.prompt_sent}
                preserveWhitespace
              />
              <DetailBlock
                icon={Clock3}
                label="Response received"
                value={selectedResult.response_received || "No response text recorded."}
                preserveWhitespace
              />
              <DetailBlock
                icon={Fingerprint}
                label="Trust Ledger entry hash"
                value={selectedResult.trust_ledger_entry_hash || "Not exposed by the current API response."}
              />
            </div>
          ) : null}
        </SheetContent>
      </Sheet>
    </div>
  );
}

interface SummaryItemProps {
  label: string;
  value: string;
}

function SummaryItem({
  label,
  value
}: SummaryItemProps) {
  return (
    <div className="rounded-[1.25rem] bg-white/5 p-4">
      <p className="text-xs uppercase tracking-[0.2em] text-slate-400">{label}</p>
      <p className="mt-3 text-lg font-semibold text-white">{value}</p>
    </div>
  );
}

interface TrendStatProps {
  label: string;
  value: string;
}

function TrendStat({
  label,
  value
}: TrendStatProps) {
  return (
    <div className="rounded-[1.25rem] bg-muted/60 px-4 py-3">
      <p className="text-[11px] uppercase tracking-[0.22em] text-muted-foreground">{label}</p>
      <p className="mt-2 text-lg font-semibold text-foreground">{value}</p>
    </div>
  );
}

interface TrendTooltipProps {
  active?: boolean;
  label?: string;
  payload?: Array<{
    payload?: TargetRiskTrendPoint;
    value?: number | string;
  }>;
}

function TrendTooltip({
  active,
  label,
  payload
}: TrendTooltipProps) {
  if (!active || !label || !payload?.length || !payload[0]?.payload) {
    return null;
  }

  const point = payload[0].payload;

  return (
    <div className="rounded-2xl border border-slate-200 bg-white px-4 py-3 shadow-lg">
      <p className="text-xs uppercase tracking-[0.22em] text-muted-foreground">{formatTooltipDate(label)}</p>
      <p className="mt-2 text-sm font-semibold text-slate-900">{point.avg_risk_score.toFixed(1)} avg risk</p>
      <p className="mt-1 text-sm text-slate-600">
        {point.total_attacks} attacks, {point.high_count} high, {point.critical_count} critical
      </p>
    </div>
  );
}

interface DetailBlockProps {
  icon: typeof ShieldAlert;
  label: string;
  value: string;
  preserveWhitespace?: boolean;
}

function DetailBlock({
  icon: Icon,
  label,
  value,
  preserveWhitespace = false
}: DetailBlockProps) {
  return (
    <section className="rounded-[1.5rem] border bg-muted/40 p-4">
      <div className="flex items-center gap-2">
        <Icon className="h-4 w-4 text-primary" />
        <p className="text-xs uppercase tracking-[0.2em] text-muted-foreground">{label}</p>
      </div>
      <p className={cn("mt-4 text-sm leading-7", preserveWhitespace ? "whitespace-pre-wrap break-words" : "break-words")}>
        {value}
      </p>
    </section>
  );
}

function normalizeRiskBreakdown(
  summary: AttackRunSummaryMeta | undefined,
  results: AttackResultResponse[]
): Record<RiskCategory, number> {
  const summaryBreakdown = summary?.risk_breakdown ?? {};

  return {
    SAFE: summaryBreakdown.SAFE ?? results.filter((result) => result.risk_category === "SAFE").length,
    LOW: summaryBreakdown.LOW ?? results.filter((result) => result.risk_category === "LOW").length,
    MEDIUM: summaryBreakdown.MEDIUM ?? results.filter((result) => result.risk_category === "MEDIUM").length,
    HIGH: summaryBreakdown.HIGH ?? results.filter((result) => result.risk_category === "HIGH").length,
    CRITICAL: summaryBreakdown.CRITICAL ?? results.filter((result) => result.risk_category === "CRITICAL").length
  };
}

function deriveRiskCategory(score: string | number | null): RiskCategory {
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

function truncateText(value: string, maxLength: number) {
  if (value.length <= maxLength) {
    return value;
  }

  return `${value.slice(0, maxLength - 1)}...`;
}

function toTitleCase(value: string) {
  return value
    .toLowerCase()
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function formatDateTime(value: string | null) {
  if (!value) {
    return "Pending";
  }

  return new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(value));
}

function shortenIdentifier(value: string) {
  if (value.length <= 12) {
    return value;
  }

  return `${value.slice(0, 8)}...${value.slice(-4)}`;
}

function formatChartDate(value: string) {
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric"
  }).format(new Date(`${value}T00:00:00Z`));
}

function formatTooltipDate(value: string) {
  return new Intl.DateTimeFormat("en-US", {
    dateStyle: "full"
  }).format(new Date(`${value}T00:00:00Z`));
}
