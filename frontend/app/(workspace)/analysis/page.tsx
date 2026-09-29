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
import { EmptyState, ErrorState, LoadingState } from "@/components/feedback/data-state";
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
  const [scanJob, setScanJob] = useState("");
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

  const runs = useQuery({ queryKey: ["analysis-runs", scopeKey], queryFn: api.analysisList, enabled: ready && hasSession });
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
      const chosenScan = scanJob || (prioritizedScan?.id ? String(prioritizedScan.id) : "");
      if (!chosenScan) throw new Error("Choose a completed scan first.");
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
  const completedScans = (scans.data?.results || []).filter((scan) => scan.status === "completed");
  const scansWithFindings = completedScans.filter((s) => (s.findings_count || 0) > 0);
  const prioritizedScan = scansWithFindings[0] || completedScans[0];
  const partialScans = (scans.data?.results || []).filter((scan) => scan.status === "partial");
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
              <div className="space-y-2">
                <Label htmlFor="analysis-scan">Completed scan</Label>
                <Select id="analysis-scan" value={scanJob || (prioritizedScan ? String(prioritizedScan.id) : "")} onChange={(event) => setScanJob(event.target.value)}>
                  <option value="">Select a scan</option>
                  {completedScans.map((scan) => (
                    <option key={scan.id} value={scan.id}>
                      #{scan.id} · {truncate(scan.target || "Scan", 26)} ({scan.findings_count ?? 0} findings · {scan.source_type})
                    </option>
                  ))}
                </Select>
                {!completedScans.length ? (
                  <p className="text-[11px] text-muted-foreground">
                    {partialScans.length
                      ? `No fully completed scans are available. ${partialScans.length} partial scan${partialScans.length === 1 ? " is" : "s are"} excluded — analysis needs complete coverage.`
                      : "No completed scans are available in this scope."}
                  </p>
                ) : null}
              </div>

              <div className="flex gap-2">
                <Button
                  type="button"
                  variant="outline"
                  className="flex-1"
                  onClick={() => {
                    const target = Number(scanJob) || completedScans[0]?.id;
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
                  disabled={start.isPending || (!scanJob && !completedScans.length)}
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
            {runs.isLoading ? (
              <div className="p-5">
                <LoadingState label="Loading analysis runs" />
              </div>
            ) : runs.isError ? (
              <div className="p-5">
                <ErrorState message={runs.error instanceof Error ? runs.error.message : undefined} onRetry={() => void runs.refetch()} />
              </div>
            ) : runs.data?.length ? (
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
                  {runs.data.map((run) => (
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
                  ))}
                </TableBody>
              </Table>
            ) : (
              <div className="p-5">
                <EmptyState title="No analysis runs" description="Start analysis from a completed scan to create the first run." />
              </div>
            )}
          </CardContent>
        </Card>
      </div>

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

function AnalysisDetailPanel({ run, loading, error, tab, onTabChange, onCancel, cancelling, onPause, pausing, onResume, resuming }: { run?: AnalysisDetail; loading: boolean; error?: string; tab: string; onTabChange: (value: string) => void; onCancel: () => void; cancelling: boolean; onPause: () => void; pausing: boolean; onResume: () => void; resuming: boolean }) {
  if (loading) return <Card><CardContent className="p-5"><LoadingState label="Loading analysis detail" /></CardContent></Card>;
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
      <div className="grid gap-3 sm:grid-cols-4">
        <SummaryMetric label="Findings processed" value={run.findings_count} />
        <SummaryMetric label="Summary assets" value={summaryStats.assets ?? rows.length} />
        <SummaryMetric label="Algorithm category" value={algoCatVal} />
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
          <div className="overflow-x-auto border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Asset</TableHead>
                  <TableHead>Category</TableHead>
                  <TableHead>Overall risk</TableHead>
                  <TableHead>Migration priority</TableHead>
                  <TableHead>Quantum</TableHead>
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

function SummaryMetric({ label, value, tone = "default" }: { label: string; value: unknown; tone?: "default" | "success" | "warning" | "danger" }) {
  const accent = tone === "success" ? "border-success/40" : tone === "warning" ? "border-warning/40" : tone === "danger" ? "border-destructive/40" : "";
  return <div className={`border p-3 ${accent}`}><p className="text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground">{label}</p><p className="tnum mt-2 truncate text-lg font-semibold" title={displayValue(value)}>{displayValue(value)}</p></div>;
}

function AssessmentView({ assessments }: { assessments: unknown[] }) {
  if (!assessments.length) return <EmptyState title="No assessments" description="No asset assessments are available for this run." />;
  return <div className="overflow-x-auto border"><Table><TableHeader><TableRow><TableHead>Asset</TableHead><TableHead>Family</TableHead><TableHead>HNDL</TableHead><TableHead>Risk</TableHead><TableHead>Recommended action</TableHead></TableRow></TableHeader><TableBody>{assessments.map((value, index) => { const item = record(value); const mosca = record(record(item.mosca).mosca_assessment); const hndl = record(item.hndl); return <TableRow key={String(item.id || index)}><TableCell><p className="font-medium">{displayValue(item.asset_name)}</p><p className="font-mono text-[11px] text-muted-foreground">{displayValue(item.asset_id)}</p></TableCell><TableCell className="text-xs">{titleCase(item.asset_family)}</TableCell><TableCell className="max-w-[180px] text-xs">{displayValue(hndl.reason || hndl.future_decryption_risk || hndl.applicable)}</TableCell><TableCell>{riskBadge(mosca.overall_risk)}</TableCell><TableCell className="max-w-[300px] text-xs text-muted-foreground">{displayValue(mosca.recommended_action || mosca.reason)}</TableCell></TableRow>; })}</TableBody></Table></div>;
}

function CbomView({ cbom, runId }: { cbom: JsonRecord; runId: number }) {
  const assets = array(cbom.crypto_assets);
  const cbomSummary = record(cbom.summary);
  return <div className="space-y-4"><div className="flex flex-wrap items-end justify-between gap-3"><div className="grid flex-1 gap-3 sm:grid-cols-3"><SummaryMetric label="Format" value={cbom.format} /><SummaryMetric label="Version" value={cbom.version} /><SummaryMetric label="Assets" value={String(assets.length)} /></div><div className="flex flex-col items-end gap-1"><SectionLabel>Export</SectionLabel><CbomExport runId={runId} /></div></div><div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4"><SummaryMetric label="Confirmed" value={formatNumber(num(cbomSummary.confirmed_assets))} tone="success" /><SummaryMetric label="Partial" value={formatNumber(num(cbomSummary.partial_assets))} tone="warning" /><SummaryMetric label="Needs review" value={formatNumber(num(cbomSummary.needs_review_assets))} tone="warning" /><SummaryMetric label="Invalid" value={formatNumber(num(cbomSummary.invalid_assets))} tone="danger" /></div>{assets.length ? <div className="overflow-x-auto border"><Table><TableHeader><TableRow><TableHead>CBOM asset</TableHead><TableHead>Algorithm</TableHead><TableHead>Family</TableHead><TableHead>Location</TableHead><TableHead>Validation</TableHead><TableHead>Confidence</TableHead></TableRow></TableHeader><TableBody>{assets.map((value, index) => { const asset = record(value); const location = record(asset.location); return <TableRow key={String(asset.asset_id || index)}><TableCell className="font-mono text-xs">{displayValue(asset.asset_id)}</TableCell><TableCell className="font-mono text-xs">{displayValue(asset.algorithm)}</TableCell><TableCell>{titleCase(asset.family)}</TableCell><TableCell className="max-w-[260px] truncate font-mono text-[11px]" title={displayValue(location.file)}>{displayValue(location.file)}</TableCell><TableCell><StatusBadge status={String(asset.validation_status || "needs_review")} /></TableCell><TableCell className="tnum">{displayValue(asset.confidence)}</TableCell></TableRow>; })}</TableBody></Table></div> : <EmptyState title="No CBOM assets" description="This analysis did not produce an inventory of cryptographic assets." />}</div>;
}
