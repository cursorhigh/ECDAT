"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, BrainCircuit, CheckCircle2, ClipboardList, Clock, Globe, Loader2, Pause, Play, ShieldAlert, SlidersHorizontal, Sparkles, XCircle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { RefreshButton } from "@/components/ui/refresh-button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label, Select, Textarea } from "@/components/ui/input";
import { Dialog } from "@/components/ui/dialog";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs } from "@/components/ui/tabs";
import { EmptyState, ErrorState } from "@/components/feedback/data-state";
import { Skeleton } from "@/components/ui/skeleton";
import { PageHeader, SectionLabel } from "@/components/data/page-header";
import { StatusBadge, riskBadge } from "@/components/data/status-badge";
import { CbomExport } from "@/components/data/cbom-export";
import { useToast } from "@/components/feedback/toast";
import { api } from "@/lib/api/client";
import { requestRiskPrompt } from "@/components/data/risk-prompt-store";
import type { AnalysisDetail, AnalysisListItem, AwaitingAnalysis, JsonRecord } from "@/lib/api/types";
import { useSession } from "@/lib/session-context";
import { formatDate, formatNumber, isTerminalStatus, refetchAllOrThrow, titleCase, truncate } from "@/lib/utils";

const terminalStatuses = new Set(["completed", "complete", "failed", "cancelled", "canceled"]);

function record(value: unknown): JsonRecord {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as JsonRecord) : {};
}

function array(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

/** Coerce an untyped API count to a number for formatting. */
function num(value: unknown) {
  return typeof value === "number" ? value : 0;
}

/*
 * Confidence is shown as a bare decimal, which on its own says nothing about
 * whether the finding should be trusted. The tooltip gives the number as a
 * percentage and says what that level actually implies, so a low score reads as
 * "worth checking" rather than as a precise measurement.
 */
function confidenceTooltip(value: number | null | undefined): string {
  if (value === null || value === undefined) return "Confidence was not recorded.";
  const pct = Math.round(value * 100);
  let meaning: string;
  if (value >= 0.9) meaning = "Parsed directly — the artefact was read, not guessed at.";
  else if (value >= 0.7) meaning = "Strong signal from a name or structure matching a known pattern.";
  else if (value >= 0.4) meaning = "Partial match. Worth reviewing before treating it as real.";
  else meaning = "Weak. Usually a name that resembles an algorithm rather than a parsed key or certificate.";
  return `${pct}% — ${meaning}`;
}

function displayValue(value: unknown) {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

/** Server-side cap on findings per analysis run. */

export default function AnalysisPage() {
  const { ready, scopeKey, info, hasSession } = useSession();
  const { pushToast } = useToast();
  const queryClient = useQueryClient();
  const [context, setContext] = useState("");
  const [selectedRunId, setSelectedRunId] = useState<number | null>(null);
  const [detailTab, setDetailTab] = useState("summary");

  // Operational Context Modal State (HNDL + Mosca)
  const [dataLifetimeYears, setDataLifetimeYears] = useState("8.0");
  const [migrationComplexity, setMigrationComplexity] = useState("3");
  const [quantumHorizonYear, setQuantumHorizonYear] = useState("2033");
  const [dataSensitivity, setDataSensitivity] = useState("4");
  const [cryptoAgility, setCryptoAgility] = useState("2");
  const [isPublicAccess, setIsPublicAccess] = useState(true);
  const [customAppName, setCustomAppName] = useState("");

  const runs = useQuery({
    queryKey: ["analysis-runs", scopeKey],
    queryFn: api.analysisList,
    enabled: ready && hasSession,
    // The rows have to move while the work does. Without this the table stayed
    // frozen at whatever it first fetched, so a run that reached 100% continued
    // to read "running" in the list while the detail panel beside it had already
    // settled -- two truths on one screen. Same 3s cadence as the detail, and it
    // stops once every run is terminal so an idle page costs nothing.
    refetchInterval: (query) => {
      const rows = query.state.data || [];
      return rows.some((run) => !terminalStatuses.has(String(run.status).toLowerCase())) ? 3000 : false;
    },
  });
  const scans = useQuery({ queryKey: ["scans", scopeKey, "created_at"], queryFn: () => api.scans({ ordering: "created_at", page: 1 }), enabled: ready && hasSession });
  const awaiting = useQuery({ queryKey: ["analysis-awaiting", scopeKey], queryFn: api.analysisAwaiting, enabled: ready && hasSession, refetchInterval: 10000 });
  const defaultRunId = runs.data?.find((run) => run.status === "completed")?.id || runs.data?.[0]?.id || null;
  const activeRunId = selectedRunId || defaultRunId;
  const detail = useQuery({ queryKey: ["analysis-detail", activeRunId, scopeKey], queryFn: () => api.analysis(activeRunId!), enabled: Boolean(activeRunId), refetchInterval: (query) => terminalStatuses.has(String(query.state.data?.status || "").toLowerCase()) ? false : 3000 });

  const buildStructuredContext = () => {
    return {
      application: {
        name: customAppName || "ECDAT Target Systems",
        type: "enterprise_service",
      },
      data: {
        lifetime_years: Number(dataLifetimeYears) || 8.0,
        sensitivity: Number(dataSensitivity) || 4,
        types: ["PII", "Financial", "SessionTokens"],
      },
      network: {
        publicly_accessible: isPublicAccess,
        internet_facing: isPublicAccess,
      },
      business_context: {
        data_retention_years: Number(dataLifetimeYears) || 8.0,
        migration_complexity: Number(migrationComplexity) || 3,
        crypto_agility: Number(cryptoAgility) || 2,
        quantum_horizon_year: Number(quantumHorizonYear) || 2033,
        assessment_year: 2026,
      },
      operational_parameters: {
        X_migration_time_years: Number(migrationComplexity) || 3.0,
        Y_data_lifetime_years: Number(dataLifetimeYears) || 8.0,
        Z_quantum_horizon_year: Number(quantumHorizonYear) || 2033,
      }
    };
  };

  const start = useMutation({
    mutationFn: () => {
      if (!targetScan) throw new Error("Run a discovery scan first.");
      const chosenScan = String(targetScan.id);
      let rawContext: any;
      if (context.trim()) {
        try { rawContext = JSON.parse(context); } catch { rawContext = context.trim(); }
      } else {
        rawContext = buildStructuredContext();
      }
      return api.startAnalysis({ scan_job: Number(chosenScan), raw_system_context: rawContext });
    },
    onSuccess: async (created) => {
      setSelectedRunId(created.id);
      setContext("");
      pushToast(`Analysis run #${created.id} is ${titleCase(created.status)}.`, "success");
      await queryClient.invalidateQueries({ queryKey: ["analysis-runs"] });
      await queryClient.invalidateQueries({ queryKey: ["analysis-detail", created.id] });
    },
    onError: (error) => pushToast(error instanceof Error ? error.message : "Analysis could not be started.", "error")
  });

  const resolve = useMutation({
    mutationFn: async (item: AwaitingAnalysis) => {
      const rawContext = buildStructuredContext();
      return api.startAnalysis({ scan_job: item.scan_job_id, raw_system_context: rawContext });
    },
    onSuccess: async (created) => {
      setSelectedRunId(created.id);
      setContext("");
      pushToast(`Operational context committed to run #${created.id}.`, "success");
      await queryClient.invalidateQueries({ queryKey: ["analysis-awaiting"] });
      await queryClient.invalidateQueries({ queryKey: ["analysis-runs"] });
    },
    onError: (error) => pushToast(error instanceof Error ? error.message : "Context could not be committed.", "error")
  });

  const cancel = useMutation({
    mutationFn: (id: number) => api.cancelAnalysis(id),
    onSuccess: async () => { pushToast("Analysis cancellation requested.", "info"); await queryClient.invalidateQueries({ queryKey: ["analysis-runs"] }); },
    onError: (error) => pushToast(error instanceof Error ? error.message : "Analysis could not be cancelled.", "error")
  });

  // Pause keeps the assessments already written; resume re-queues the run and
  // skips them, so pausing costs at most one asset rather than a restart.
  const pause = useMutation({
    mutationFn: (id: number) => api.pauseAnalysis(id),
    onSuccess: async (run) => {
      pushToast(`Analysis #${run.id} paused at ${run.progress}%.`, "info");
      await refetchRun();
    },
    onError: (error) => pushToast(error instanceof Error ? error.message : "Analysis could not be paused.", "error")
  });

  const resume = useMutation({
    mutationFn: (id: number) => api.resumeAnalysis(id),
    onSuccess: async (run) => {
      pushToast(`Analysis #${run.id} resumed. Assets already assessed are re-used.`, "success");
      await refetchRun();
    },
    onError: (error) => pushToast(error instanceof Error ? error.message : "Analysis could not be resumed.", "error")
  });

  const refresh = async () => {
    await refetchAllOrThrow([runs, scans, awaiting]);
    if (activeRunId) await refetchAllOrThrow([detail]);
  };
  // Pause/resume change the run's own status, so the list and the detail both
  // need to come back, not just the one the user is looking at.
  const refetchRun = async () => {
    await queryClient.invalidateQueries({ queryKey: ["analysis-runs"] });
    if (activeRunId) await queryClient.invalidateQueries({ queryKey: ["analysis-detail", activeRunId] });
  };
  const partialScans = (scans.data?.results || []).filter((scan) => scan.status === "partial");
  /*
   * Anything that finished producing evidence is analysable, partial included --
   * a partial run records its own coverage gap on the assessment rather than
   * being refused. Only scans still queued or running are excluded, because there
   * is nothing settled to reason over yet.
   *
   * The newest one is already selected, so there is no dropdown to drive. A scan
   * with findings outranks an empty one so a bare "no findings" run does not
   * become the default.
   */
  const completedScans = (scans.data?.results || []).filter(
    (scan) => scan.status === "completed" || scan.status === "partial"
  );
  const scansWithFindings = completedScans.filter((s) => (s.findings_count || 0) > 0);
  const targetScan = scansWithFindings[0] || completedScans[0] || null;
  const awaitingRows = awaiting.data || [];

  // Anything the operator can still act on. `awaiting_context` counts as live
  // because the context window is still open, but it is not pausable.
  const controlBusy = pause.isPending || resume.isPending || cancel.isPending;
  const liveRun = (runs.data || []).find((run) => !isTerminalStatus(run.status) || run.status === "paused") || null;

  return (
    <div className="space-y-6">
      <PageHeader compact eyebrow="Analysis segment" title="Risk analysis" description="Start or resume analysis runs, resolve HNDL & Mosca operational parameters, and inspect quantum risk assessments." actions={<RefreshButton onRefresh={refresh} />} />

      {/* Awaiting Context Notification Bar */}
      {awaitingRows.length ? (
        <Card className="border-warning/40 bg-warning/5">
          <CardContent className="p-4">
            <div className="flex items-start gap-3">
              <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-warning" aria-hidden="true" />
              <div className="min-w-0 flex-1">
                <h2 className="text-sm font-semibold">HNDL & Mosca Context Decision Required</h2>
                <p className="mt-1 text-xs leading-5 text-muted-foreground">
                  The analysis paused before execution. Specify the operational data shelf-life (Y) and migration window (X) parameters to proceed.
                </p>
                <p className="mt-3 text-xs leading-5 text-foreground">
                  The parameters window is already open. If it closes without an
                  answer, the run continues on conservative defaults when the window
                  expires.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      ) : null}


      <div className="grid gap-4 xl:grid-cols-[0.85fr_1.4fr]">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <BrainCircuit className="h-4 w-4 text-primary" aria-hidden="true" />
              Start analysis
            </CardTitle>
            <p className="mt-1 text-xs leading-5 text-muted-foreground">
              Analyzes every finding the completed scan discovered, with no coverage cap.
            </p>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {/* No dropdown. With one job per discovery run, there is one obvious
                  scan to analyse: the most recent one that finished. The picker
                  only earns its space when there is a genuine choice to make. */}
              <div className="space-y-2">
                <p className="text-xs text-muted-foreground">Scan</p>
                {targetScan ? (
                  <div className="border bg-muted/30 px-2.5 py-2">
                    <p className="truncate text-sm font-medium" title={targetScan.target || undefined}>
                      #{targetScan.id} · {truncate(targetScan.target || "Scan", 30)}
                    </p>
                    <p className="mt-0.5 text-[11px] text-muted-foreground">
                      {formatNumber(targetScan.findings_count ?? 0)} findings
                      {targetScan.status === "partial" ? " · partial coverage" : ""}
                    </p>
                  </div>
                ) : (
                  <p className="text-[11px] text-muted-foreground">
                    {partialScans.length
                      ? `${partialScans.length} partial scan${partialScans.length === 1 ? " is" : "s are"} available. A partial scan can still be analysed, with its coverage gap recorded.`
                      : "No finished scan is available in this scope. Run a discovery scan first."}
                  </p>
                )}
              </div>

              <div className="flex gap-2">
                <Button
                  type="button"
                  variant="outline"
                  className="flex-1"
                  onClick={() => {
                    const target = targetScan?.id;
                    if (!target) {
                      pushToast("No completed scan is available to analyze.", "error");
                      return;
                    }
                    requestRiskPrompt({ kind: "start", scanJobId: target });
                  }}
                >
                  <SlidersHorizontal className="h-3.5 w-3.5" aria-hidden="true" />
                  Customize Mosca & HNDL
                </Button>
                <Button
                  className="flex-1"
                  onClick={() => start.mutate()}
                  disabled={start.isPending || !targetScan}
                >
                  {start.isPending ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                  ) : (
                    <Play className="h-3.5 w-3.5" aria-hidden="true" />
                  )}
                  Start Analysis
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex-row items-start justify-between gap-4">
            <div>
              <CardTitle>Analysis runs</CardTitle>
              <p className="mt-1 text-xs text-muted-foreground">Analysis lifecycle: queued → running → completed, failed, or cancelled.</p>
              <p className="mt-1 text-xs text-muted-foreground">A paused run keeps its completed assessments; resuming picks up from the next unassessed asset.</p>
            </div>
            <div className="flex shrink-0 items-center gap-3">
              {liveRun ? (
                <div className="flex items-center gap-2 border bg-muted/40 px-2.5 py-1.5">
                  <StatusBadge status={liveRun.status} />
                  <span className="font-mono text-[11px] text-muted-foreground">#{liveRun.id}</span>
                  <RunControlButtons
                    runId={liveRun.id}
                    status={liveRun.status}
                    busy={controlBusy}
                    onPause={() => pause.mutate(liveRun.id)}
                    onResume={() => resume.mutate(liveRun.id)}
                    onCancel={() => cancel.mutate(liveRun.id)}
                  />
                </div>
              ) : null}
              <ClipboardList className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
            </div>
          </CardHeader>
          <CardContent className="p-0">
            {/*
             * `isPending`, not `isLoading`. This query is `enabled: ready &&
             * hasSession`, and a query that is merely disabled reports
             * `isLoading === false` while `isPending === true`. Keying off
             * `isLoading` therefore fell through to the empty state and claimed
             * "No analysis runs" during the moment before the session resolved --
             * a flash of a false claim on every page load.
             */}
            {runs.isPending ? (
              // Table-shaped, for the same reason as the detail panel: a loader
              // that matches what it replaces keeps the column widths from
              // jumping when the rows arrive.
              <div className="p-5" role="status" aria-live="polite">
                <div className="mb-4 flex items-center gap-2 text-xs text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                  Loading analysis runs
                </div>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Run</TableHead>
                      <TableHead>Target</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Progress</TableHead>
                      <TableHead>Assets</TableHead>
                      <TableHead />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {[0, 1, 2, 3, 4].map((row) => (
                      <TableRow key={row}>
                        <TableCell><Skeleton className="h-4 w-14" /></TableCell>
                        <TableCell><Skeleton className="h-4 w-48" /></TableCell>
                        <TableCell><Skeleton className="h-5 w-20 rounded-full" /></TableCell>
                        <TableCell><div className="flex items-center gap-2"><Skeleton className="h-2 w-20" /><Skeleton className="h-3 w-8" /></div></TableCell>
                        <TableCell><Skeleton className="h-4 w-8" /></TableCell>
                        <TableCell><Skeleton className="h-8 w-20" /></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            ) : runs.isError ? (
              <div className="p-5">
                <ErrorState message={runs.error instanceof Error ? runs.error.message : undefined} onRetry={() => void runs.refetch()} />
              </div>
            ) : runs.data?.length ? (
              /*
               * Bounded and scrollable, with a sticky header. This list grows by
               * one row per analysis ever started and nothing capped it, so after
               * a few dozen runs the card pushed the detail panel clean off the
               * screen. `overflow-y-auto` keeps the list a fixed panel and lets it
               * scroll within itself; the header is sticky so the columns stay
               * named while you scroll to find a run.
               */
              <div className="max-h-[26rem] overflow-y-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="sticky top-0 z-10 bg-card">Run</TableHead>
                    <TableHead className="sticky top-0 z-10 bg-card">Target</TableHead>
                    <TableHead className="sticky top-0 z-10 bg-card">Status</TableHead>
                    <TableHead className="sticky top-0 z-10 bg-card">Progress</TableHead>
                    <TableHead className="sticky top-0 z-10 bg-card">Assets</TableHead>
                    <TableHead />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {runs.data.map((rowRun) => {
                    /*
                     * The selected row is rendered from the live detail, not from
                     * the list. The two come from different endpoints and are
                     * fetched a moment apart, so they genuinely disagree -- the
                     * header could read "Terminal state 100%" while the row it
                     * belongs to still said 60%, or showed pause controls for a
                     * run that had already finished. Since the detail is the
                     * authoritative view of the run being examined, its live
                     * status, progress and asset count win here.
                     */
                    const live = rowRun.id === activeRunId ? detail.data : undefined;
                    const run: AnalysisListItem = live
                      ? {
                          ...rowRun,
                          status: live.status ?? rowRun.status,
                          progress: live.progress ?? rowRun.progress,
                          // The list item's `assets` is the count the table shows;
                          // the detail carries the same number as its assessment
                          // list, which is what the tab badge counts too.
                          assets: array(live.assessments).length || rowRun.assets,
                        }
                      : rowRun;
                    return (
                    <AnalysisRow
                      key={run.id}
                      run={run}
                      selected={run.id === activeRunId}
                      onSelect={() => {
                        setSelectedRunId(run.id);
                        setDetailTab("summary");
                      }}
                      controls={
                        <RunControlButtons
                          runId={run.id}
                          status={run.status}
                          busy={controlBusy}
                          onPause={() => pause.mutate(run.id)}
                          onResume={() => resume.mutate(run.id)}
                          onCancel={() => cancel.mutate(run.id)}
                        />
                      }
                    />
                    );
                  })}
                </TableBody>
              </Table>
              </div>
            ) : (
              <div className="p-5">
                <EmptyState title="No analysis runs" description="Start analysis from a completed scan to create the first run." />
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/*
       * Full width. This is the third child of a two-column grid, so it wrapped
       * onto its own row in the narrow 0.85fr track -- the primary content was
       * confined to a column sized for a side form, which is what pushed its
       * five-column tables into horizontal scrolling. Spanning both tracks gives
       * it the width the tables were laid out for.
       */}
      <div className="xl:col-span-2">
      {activeRunId ? (
        <AnalysisDetailPanel
          run={detail.data}
          loading={detail.isLoading}
          error={detail.error instanceof Error ? detail.error.message : undefined}
          tab={detailTab}
          onTabChange={setDetailTab}
          onCancel={() => cancel.mutate(activeRunId)}
          cancelling={cancel.isPending}
          onPause={() => pause.mutate(activeRunId)}
          pausing={pause.isPending}
          onResume={() => resume.mutate(activeRunId)}
          resuming={resume.isPending}
        />
      ) : (
        <Card>
          <CardContent className="p-5">
            <EmptyState title="Select an analysis run" description="Choose a run above to inspect its summary and assessments." />
          </CardContent>
        </Card>
      )}
      </div>
    </div>
  );
}

/**
 * Pause / Resume / Cancel for a single run.
 *
 * Which buttons appear is derived from the status rather than hard-coded at the
 * call site, so the same component is safe in the table, the detail header, and
 * the runs-card header. Pause is deliberately not offered for
 * `awaiting_context`: that run has not started, and the backend would reject a
 * pause with a 400, so showing one would only produce a dead control.
 */
function RunControlButtons({ runId, status, onPause, onResume, onCancel, busy }: { runId: number; status: string; onPause: () => void; onResume: () => void; onCancel: () => void; busy: boolean }) {
  const key = (status || "").toLowerCase();
  const isPaused = key === "paused";
  const canPause = key === "running" || key === "queued";
  const canCancel = !isTerminalStatus(status);
  if (!isPaused && !canPause && !canCancel) return null;
  return (
    <div className="flex items-center gap-1.5">
      {isPaused ? (
        <Button size="sm" variant="outline" onClick={onResume} disabled={busy} aria-label={`Resume run ${runId}`}>
          <Play className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
          Resume
        </Button>
      ) : null}
      {canPause ? (
        <Button size="sm" variant="outline" onClick={onPause} disabled={busy} aria-label={`Pause run ${runId}`}>
          <Pause className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
          Pause
        </Button>
      ) : null}
      {canCancel ? (
        <Button size="sm" variant="outline" onClick={onCancel} disabled={busy} aria-label={`Cancel run ${runId}`}>
          <XCircle className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
          Cancel
        </Button>
      ) : null}
    </div>
  );
}

function AnalysisRow({ run, selected, onSelect, controls }: { run: AnalysisListItem; selected: boolean; onSelect: () => void; controls: React.ReactNode }) {
  return <TableRow className={selected ? "bg-primary/5" : undefined}><TableCell><button type="button" onClick={onSelect} className="font-mono text-xs font-semibold hover:text-primary">#{run.id}</button><p className="mt-0.5 text-[11px] text-muted-foreground">{formatDate(run.created_at)}</p></TableCell><TableCell><p className="max-w-[250px] truncate text-sm">{run.target || "—"}</p></TableCell><TableCell><StatusBadge status={run.status} /></TableCell><TableCell><div className="flex min-w-28 items-center gap-2"><Progress value={run.progress} className="w-20" /><span className="tnum text-[11px] text-muted-foreground">{run.progress}%</span></div></TableCell><TableCell className="tnum">{formatNumber(run.assets)}</TableCell><TableCell><div className="flex items-center gap-2"><Button variant={selected ? "secondary" : "ghost"} size="sm" onClick={onSelect}>{selected ? "Selected" : "View"}</Button>{controls}</div></TableCell></TableRow>;
}

/**
 * A loader shaped like the panel it stands in for.
 *
 * The shared `LoadingState` is a four-across grid of tall cards over one big
 * block -- right for a full-width page, wrong for this panel, which is a header,
 * a progress bar, a tab strip and then a metrics row. Dropping the shared
 * skeleton in here made the panel jump when the content arrived. Mirroring the
 * real layout means the transition is only the values filling in.
 *
 * `runId` keeps the header reading "Run #N" while loading, so the loader stays
 * attached to the run that was clicked instead of blanking back to nothing.
 */
function AnalysisDetailSkeleton({ runId }: { runId?: number }) {
  return (
    <Card aria-busy="true">
      <CardHeader className="flex-row items-start justify-between">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <Skeleton className="h-4 w-24" />
            <Skeleton className="h-5 w-20 rounded-full" />
          </div>
          <Skeleton className="mt-2 h-4 w-2/3 max-w-xl" />
          <Skeleton className="mt-1.5 h-3 w-52" />
        </div>
        <div className="flex shrink-0 gap-2">
          <Skeleton className="h-8 w-20" />
          <Skeleton className="h-8 w-20" />
        </div>
      </CardHeader>
      <div className="border-b px-5 pt-4">
        <Skeleton className="h-1.5 w-full" />
        <div className="flex justify-between py-2">
          <Skeleton className="h-3 w-32" />
          <Skeleton className="h-3 w-8" />
        </div>
      </div>
      <div className="px-5 pt-3">
        <div className="flex gap-4">
          <Skeleton className="h-4 w-16" />
          <Skeleton className="h-4 w-24" />
          <Skeleton className="h-4 w-12" />
        </div>
      </div>
      <CardContent className="space-y-6 p-5">
        <div className="grid gap-3 sm:grid-cols-4">
          {[0, 1, 2, 3].map((item) => (
            <div key={item} className="border p-4">
              <Skeleton className="h-3 w-24" />
              <Skeleton className="mt-2 h-5 w-16" />
            </div>
          ))}
        </div>
        <div className="grid gap-4 lg:grid-cols-2">
          <Skeleton className="h-52" />
          <Skeleton className="h-52" />
        </div>
      </CardContent>
    </Card>
  );
}

function AnalysisDetailPanel({ run, loading, error, tab, onTabChange, onCancel, cancelling, onPause, pausing, onResume, resuming }: { run?: AnalysisDetail; loading: boolean; error?: string; tab: string; onTabChange: (value: string) => void; onCancel: () => void; cancelling: boolean; onPause: () => void; pausing: boolean; onResume: () => void; resuming: boolean }) {
  if (loading) return <AnalysisDetailSkeleton runId={run?.id} />;
  if (error) return <Card><CardContent className="p-5"><ErrorState message={error} /></CardContent></Card>;
  if (!run) return <Card><CardContent className="p-5"><EmptyState title="Analysis detail unavailable" description="The selected run is outside the active scope or has not returned data." /></CardContent></Card>;
  const summary = record(run.executive_summary);
  const summaryStats = record(summary.stats);
  const context = record(run.risk_context);
  const dataContext = record(context.data_context);
  const networkContext = record(context.network_context);
  const assessmentRows = array(run.assessments);
  const runStatus = (run.status || "").toLowerCase();
  const isPaused = runStatus === "paused";
  return <Card><CardHeader className="flex-row items-start justify-between"><div><div className="flex flex-wrap items-center gap-2"><SectionLabel>Run #{run.id}</SectionLabel><StatusBadge status={run.status} />{isPaused ? <span className="text-[11px] text-muted-foreground">Paused — assessed assets are kept and reused on resume.</span> : null}</div><p className="mt-2 max-w-2xl truncate text-sm text-muted-foreground" title={run.target}>{run.target || "No target reported"}</p><p className="mt-1 text-xs text-muted-foreground">Started {formatDate(run.started_at || run.created_at)}{run.finished_at ? ` · Finished ${formatDate(run.finished_at)}` : ""}</p></div><RunControlButtons runId={run.id} status={run.status} busy={cancelling || pausing || resuming} onPause={onPause} onResume={onResume} onCancel={onCancel} /></CardHeader><div className="border-b px-5 pt-4"><Progress value={run.progress} /><div className="flex justify-between py-2 text-[11px] text-muted-foreground"><span>{isTerminalStatus(run.status) ? "Terminal state" : "Refreshing analysis state"}</span><span className="tnum">{run.progress}%</span></div></div><div className="px-5 pt-3"><Tabs value={tab} onValueChange={onTabChange} items={[{ value: "summary", label: "Summary" }, { value: "assessments", label: "Assessments", count: assessmentRows.length }, { value: "cbom", label: "CBOM" }]} /></div><CardContent className="p-5"><div>{run.truncation?.truncated ? <div className="mb-5 flex gap-2 border border-warning/40 bg-warning/5 p-3 text-xs leading-5 text-warning"><AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" /><span>This analysis assessed {formatNumber(run.truncation.analysed)} of {formatNumber(run.truncation.available)} discovered findings{run.truncation.limit ? ` (limit ${formatNumber(run.truncation.limit)})` : ""}. Every result below describes only the assessed subset, not the whole scan.</span></div> : null}{run.error ? <div className="mb-5 flex gap-2 border border-destructive/30 bg-destructive/5 p-3 text-xs leading-5 text-destructive"><XCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />{run.error}</div> : null}{tab === "summary" ? <SummaryView run={run} summary={summary} summaryStats={summaryStats} dataContext={dataContext} networkContext={networkContext} /> : tab === "assessments" ? <AssessmentView assessments={assessmentRows} /> : <CbomView cbom={record(run.cbom)} runId={run.id} />}</div></CardContent></Card>;
}

function SummaryView({ run, summary, summaryStats, dataContext, networkContext }: { run: AnalysisDetail; summary: JsonRecord; summaryStats: JsonRecord; dataContext: JsonRecord; networkContext: JsonRecord }) {
  const narrative = [summary.narrative, summary.executive_summary_text].find(
    (value): value is string => typeof value === "string" && value.trim().length > 0,
  );
  const rows = run.summary_rows || [];
  const riskCtx = record(run.risk_context);
  const rawCtx = record(run.raw_system_context);
  const rawData = record(rawCtx.data);
  const rawNet = record(rawCtx.network);
  const rawBiz = record(rawCtx.business_context);

  const sensitivityVal = dataContext.sensitivity ?? rawData.sensitivity ?? riskCtx.data_sensitivity ?? "Tier 4 (High)";
  const rawYears = dataContext.data_lifetime_years ?? rawData.lifetime_years ?? rawBiz.data_retention_years ?? riskCtx.data_lifetime_years;
  const lifetimeVal = rawYears ? `${rawYears} years` : "8.0 years";
  
  const rawExposed = networkContext.internet_exposed ?? rawNet.internet_facing ?? rawNet.publicly_accessible ?? riskCtx.internet_exposed;
  const exposedVal = typeof rawExposed === "boolean" ? (rawExposed ? "Public / Internet" : "Internal / Mesh") : (rawExposed ? String(rawExposed) : "Public / Internet");

  const rawCollectable = networkContext.collectable ?? riskCtx.HNDL_exposure ?? (summaryStats.hndl_applicable ? "High (HNDL Active)" : "Standard");
  const collectableVal = typeof rawCollectable === "boolean" ? (rawCollectable ? "High" : "Low") : String(rawCollectable);

  const algoCatVal = summary.algorithm_category || (rows[0]?.algorithm_category ? titleCase(rows[0].algorithm_category) : "PUBLIC_KEY");

  return (
    <div className="space-y-6">
      {/*
       * Three metrics across four tracks, so the third was squeezed into a
       * quarter of the width and truncated the category list mid-token
       * ("AES / HASH / PQC / PUBLIC_KEY / S"). Giving it two tracks doubles its
       * width and uses the row exactly: 1 + 1 + 2 = 4. The category is a list,
       * so it needs the room far more than the two counts do.
       */}
      <div className="grid gap-3 sm:grid-cols-4">
        <SummaryMetric label="Findings processed" value={run.findings_count} />
        <SummaryMetric label="Summary assets" value={summaryStats.assets ?? rows.length} />
        <SummaryMetric label="Algorithm category" value={algoCatVal} className="sm:col-span-2" wrap />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="border bg-muted/20 p-4">
          <SectionLabel>Risk context</SectionLabel>
          <div className="mt-3 space-y-2 text-xs">
            <div className="flex justify-between gap-4">
              <span className="text-muted-foreground">Data sensitivity</span>
              <span className="font-medium text-foreground">{displayValue(sensitivityVal)}</span>
            </div>
            <div className="flex justify-between gap-4">
              <span className="text-muted-foreground">Data lifetime</span>
              <span className="font-medium text-foreground">{displayValue(lifetimeVal)}</span>
            </div>
            <div className="flex justify-between gap-4">
              <span className="text-muted-foreground">Internet exposed</span>
              <span className="font-medium text-foreground">{displayValue(exposedVal)}</span>
            </div>
            <div className="flex justify-between gap-4">
              <span className="text-muted-foreground">Collectable</span>
              <span className="font-medium text-foreground">{displayValue(collectableVal)}</span>
            </div>
          </div>
        </div>

        <div className="border bg-muted/20 p-4">
          <SectionLabel>Executive summary</SectionLabel>
          <div className="mt-3 grid gap-3 sm:grid-cols-4">
            <SummaryMetric label="Assets assessed" value={formatNumber(num(summaryStats.assets ?? rows.length))} />
            <SummaryMetric label="Urgent" value={formatNumber(num(summaryStats.urgent))} tone="danger" />
            <SummaryMetric label="Critical" value={formatNumber(num(summaryStats.critical))} tone="danger" />
            <SummaryMetric label="HNDL applicable" value={formatNumber(num(summaryStats.hndl_applicable))} tone="warning" />
          </div>
          {narrative ? (
            <p className="mt-3 text-sm leading-6">{narrative}</p>
          ) : (
            <p className="mt-3 text-xs text-muted-foreground">This run reports structured results only; no written narrative was returned.</p>
          )}
        </div>
      </div>

      <div>
        <div className="mb-3 flex items-center justify-between">
          <SectionLabel>Summary rows</SectionLabel>
          <span className="text-[11px] text-muted-foreground">Sorted by migration priority</span>
        </div>
        {rows.length ? (
          /* One row per assessed asset, so this is as long as the assessments tab
             -- 371 rows here. Horizontal scrolling alone was not enough; the
             height is capped so the summary metrics above stay on screen and the
             table scrolls within its own bordered panel. */
          <div className="max-h-[32rem] overflow-auto border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="sticky top-0 z-10 bg-card">Asset</TableHead>
                  <TableHead className="sticky top-0 z-10 bg-card">Category</TableHead>
                  <TableHead className="sticky top-0 z-10 bg-card">Overall risk</TableHead>
                  <TableHead className="sticky top-0 z-10 bg-card">Migration priority</TableHead>
                  <TableHead className="sticky top-0 z-10 bg-card">Quantum</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((row, index) => (
                  <TableRow key={`${row.asset_id}-${index}`}>
                    <TableCell className="font-mono text-xs">{displayValue(row.asset_id)}</TableCell>
                    <TableCell className="text-xs">{titleCase(row.algorithm_category)}</TableCell>
                    <TableCell>{riskBadge(row.overall_risk)}</TableCell>
                    <TableCell>{riskBadge(row.migration_priority)}</TableCell>
                    <TableCell>{row.quantum_vulnerable ? <Badge variant="danger">Yes</Badge> : <Badge>No</Badge>}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ) : (
          <EmptyState title="No summary rows" description="The run completed without returning summary rows." />
        )}
      </div>
    </div>
  );
}

function SummaryMetric({ label, value, tone = "default", className, wrap = false }: { label: string; value: unknown; tone?: "default" | "success" | "warning" | "danger"; className?: string; wrap?: boolean }) {
  const accent = tone === "success" ? "border-success/40" : tone === "warning" ? "border-warning/40" : tone === "danger" ? "border-destructive/40" : "";
  return <div className={`border p-3 ${accent} ${className || ""}`}><p className="text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground">{label}</p><p className={`tnum mt-2 text-lg font-semibold ${wrap ? "break-words" : "truncate"}`} title={displayValue(value)}>{displayValue(value)}</p></div>;
}

function AssessmentView({ assessments }: { assessments: unknown[] }) {
  if (!assessments.length) return <EmptyState title="No assessments" description="No asset assessments are available for this run." />;
  /*
   * Both axes scroll, and the height is bounded. A run over a real target
   * produces one assessment per asset -- 371 of them for this one -- and the
   * table had only `overflow-x-auto`, so the page grew to 371 rows tall and the
   * header, tabs and controls were all scrolled out of reach. Capping the height
   * keeps the surrounding panel usable and lets the list scroll inside itself,
   * with sticky headers so Asset/Family/HNDL/Risk stay named throughout.
   */
  return <div className="max-h-[32rem] overflow-auto border"><Table><TableHeader><TableRow><TableHead className="sticky top-0 z-10 bg-card">Asset</TableHead><TableHead className="sticky top-0 z-10 bg-card">Family</TableHead><TableHead className="sticky top-0 z-10 bg-card">HNDL</TableHead><TableHead className="sticky top-0 z-10 bg-card">Risk</TableHead><TableHead className="sticky top-0 z-10 bg-card">Recommended action</TableHead></TableRow></TableHeader><TableBody>{assessments.map((value, index) => { const item = record(value); const mosca = record(record(item.mosca).mosca_assessment); const hndl = record(item.hndl); return <TableRow key={String(item.id || index)}><TableCell><p className="font-medium">{displayValue(item.asset_name)}</p><p className="font-mono text-[11px] text-muted-foreground">{displayValue(item.asset_id)}</p></TableCell><TableCell className="text-xs">{titleCase(item.asset_family)}</TableCell><TableCell className="max-w-[180px] text-xs">{displayValue(hndl.reason || hndl.future_decryption_risk || hndl.applicable)}</TableCell><TableCell>{riskBadge(mosca.overall_risk)}</TableCell><TableCell className="max-w-[300px] text-xs text-muted-foreground">{displayValue(mosca.recommended_action || mosca.reason)}</TableCell></TableRow>; })}</TableBody></Table></div>;
}

function CbomView({ cbom, runId }: { cbom: JsonRecord; runId: number }) {
  const assets = array(cbom.crypto_assets);
  const cbomSummary = record(cbom.summary);
  return <div className="space-y-4"><div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
          <div className="grid flex-1 gap-3 sm:grid-cols-3">
            <SummaryMetric label="Format" value={cbom.format} />
            <SummaryMetric label="Version" value={cbom.version} />
            <SummaryMetric label="Assets" value={String(assets.length)} />
          </div>
          {/*
           * Top-aligned with the metrics rather than bottom-aligned to them. The
           * group was `items-end` in a flex row of its own, so it hung off the
           * bottom-right corner of the metric strip and drifted down as the boxes
           * changed height. It also needs the full width on narrow screens,
           * where three stacked buttons would otherwise be squeezed.
           */}
          <div className="flex shrink-0 flex-col gap-1.5 lg:w-auto lg:max-w-md lg:items-end">
            <SectionLabel className="lg:text-right">Export</SectionLabel>
            <CbomExport runId={runId} />
          </div>
        </div><div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4"><SummaryMetric label="Confirmed" value={formatNumber(num(cbomSummary.confirmed_assets))} tone="success" /><SummaryMetric label="Partial" value={formatNumber(num(cbomSummary.partial_assets))} tone="warning" /><SummaryMetric label="Needs review" value={formatNumber(num(cbomSummary.needs_review_assets))} tone="warning" /><SummaryMetric label="Invalid" value={formatNumber(num(cbomSummary.invalid_assets))} tone="danger" /></div>{/*
         * One row per crypto asset, and this run has 371 of them. It had
         * horizontal scrolling only, so the page grew until the export controls
         * and the validation summary were scrolled out of reach. Bounded height,
         * scrolls within its own panel, header stays named.
         */}
        {assets.length ? <div className="max-h-[32rem] overflow-auto border"><Table><TableHeader><TableRow><TableHead className="sticky top-0 z-10 bg-card" title="The identifier ECDAT assigned to this asset. It is the key used to join this row to the assessments and the dependency graph.">CBOM asset</TableHead><TableHead className="sticky top-0 z-10 bg-card" title="The algorithm in use on this asset.">Algorithm</TableHead><TableHead className="sticky top-0 z-10 bg-card" title="The algorithm family - RSA, ECC, AES, PQC and so on. The family, rather than the exact algorithm name, is what drives migration priority.">Family</TableHead><TableHead className="sticky top-0 z-10 bg-card" title="The file this asset was found in, so the finding can be traced back to its source.">Location</TableHead><TableHead className="sticky top-0 z-10 bg-card" title="How far ECDAT could verify the asset: confirmed it parsed cleanly, only partially identified it, found it invalid, or could not decide and left it for review.">Validation</TableHead><TableHead className="sticky top-0 z-10 bg-card" title="How sure discovery is that this is a real cryptographic artefact, from 0 to 1.">Confidence</TableHead></TableRow></TableHeader><TableBody>{assets.map((value, index) => { const asset = record(value); const location = record(asset.location); return <TableRow key={String(asset.asset_id || index)}><TableCell className="font-mono text-xs" title={displayValue(asset.asset_id)}>{displayValue(asset.asset_id)}</TableCell><TableCell className="font-mono text-xs" title={displayValue(asset.algorithm)}>{displayValue(asset.algorithm)}</TableCell><TableCell title={titleCase(asset.family)}>{titleCase(asset.family)}</TableCell><TableCell className="max-w-[260px] truncate font-mono text-[11px]" title={displayValue(location.file)}>{displayValue(location.file)}</TableCell><TableCell><StatusBadge status={String(asset.validation_status || "needs_review")} /></TableCell><TableCell className="tnum" title={confidenceTooltip(num(asset.confidence))}>{displayValue(asset.confidence)}</TableCell></TableRow>; })}</TableBody></Table></div> : <EmptyState title="No CBOM assets" description="This analysis did not produce an inventory of cryptographic assets." />}</div>;
}
