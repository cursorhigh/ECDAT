"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, BrainCircuit, CheckCircle2, ClipboardList, Clock, Globe, Loader2, Play, ShieldAlert, SlidersHorizontal, Sparkles, XCircle } from "lucide-react";
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
const ANALYSIS_MAX_FINDINGS = 500;

export default function AnalysisPage() {
  const { ready, scopeKey, info, hasSession } = useSession();
  const { pushToast } = useToast();
  const queryClient = useQueryClient();
  const [scanJob, setScanJob] = useState("");
  const [maxFindings, setMaxFindings] = useState(String(ANALYSIS_MAX_FINDINGS));
  const [context, setContext] = useState("");
  const [selectedRunId, setSelectedRunId] = useState<number | null>(null);
  const [detailTab, setDetailTab] = useState("summary");

  // Operational Context Modal State (HNDL + Mosca)
  const [dialogOpen, setDialogOpen] = useState(false);
  const [targetAwaitingItem, setTargetAwaitingItem] = useState<AwaitingAnalysis | null>(null);
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
      return api.startAnalysis({ scan_job: Number(chosenScan), max_findings: Number(maxFindings) || undefined, raw_system_context: rawContext });
    },
    onSuccess: async (created) => {
      setSelectedRunId(created.id);
      setContext("");
      setDialogOpen(false);
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
      setDialogOpen(false);
      setTargetAwaitingItem(null);
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

  const refresh = async () => {
    await refetchAllOrThrow([runs, scans, awaiting]);
    if (activeRunId) await refetchAllOrThrow([detail]);
  };
  const completedScans = (scans.data?.results || []).filter((scan) => scan.status === "completed");
  const scansWithFindings = completedScans.filter((s) => (s.findings_count || 0) > 0);
  const prioritizedScan = scansWithFindings[0] || completedScans[0];
  const partialScans = (scans.data?.results || []).filter((scan) => scan.status === "partial");
  const awaitingRows = awaiting.data || [];

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
                <div className="mt-3 flex flex-wrap items-center gap-3">
                  <Button
                    size="sm"
                    onClick={() => {
                      setTargetAwaitingItem(awaitingRows[0]);
                      setDialogOpen(true);
                    }}
                  >
                    <SlidersHorizontal className="h-3.5 w-3.5" aria-hidden="true" />
                    Configure HNDL & Mosca Parameters
                  </Button>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      ) : null}

      {/* Operational Context Dialog */}
      <Dialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        title="Operational Threat & Timeline Parameters"
        description="Provide organizational context for Michele Mosca's Theorem (X + Y > Z) and HNDL (Harvest-Now-Decrypt-Later) Threat Scoring."
        footer={
          <>
            <Button variant="ghost" onClick={() => setDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => {
                if (targetAwaitingItem) {
                  resolve.mutate(targetAwaitingItem);
                } else {
                  start.mutate();
                }
              }}
              disabled={start.isPending || resolve.isPending}
            >
              {start.isPending || resolve.isPending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <CheckCircle2 className="h-3.5 w-3.5" />
              )}
              {targetAwaitingItem ? "Commit Parameters & Run" : "Start Analysis With Parameters"}
            </Button>
          </>
        }
      >
        <div className="space-y-4 text-xs">
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label className="flex items-center gap-1.5 font-medium">
                <Clock className="h-3.5 w-3.5 text-primary" />
                Data Shelf-Life (Y years)
              </Label>
              <Input
                type="number"
                step="0.5"
                value={dataLifetimeYears}
                onChange={(e) => setDataLifetimeYears(e.target.value)}
                placeholder="e.g. 8.0"
              />
              <p className="text-[10px] text-muted-foreground">Years data must remain secret.</p>
            </div>

            <div className="space-y-1.5">
              <Label className="flex items-center gap-1.5 font-medium">
                <SlidersHorizontal className="h-3.5 w-3.5 text-primary" />
                Migration Duration (X years)
              </Label>
              <Input
                type="number"
                step="0.5"
                value={migrationComplexity}
                onChange={(e) => setMigrationComplexity(e.target.value)}
                placeholder="e.g. 3.0"
              />
              <p className="text-[10px] text-muted-foreground">Estimated time to migrate systems.</p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label className="flex items-center gap-1.5 font-medium">
                <Sparkles className="h-3.5 w-3.5 text-warning" />
                CRQC Arrival Horizon (Z)
              </Label>
              <Input
                type="number"
                value={quantumHorizonYear}
                onChange={(e) => setQuantumHorizonYear(e.target.value)}
                placeholder="e.g. 2033"
              />
              <p className="text-[10px] text-muted-foreground">Estimated year of Quantum arrival.</p>
            </div>

            <div className="space-y-1.5">
              <Label className="flex items-center gap-1.5 font-medium">
                <ShieldAlert className="h-3.5 w-3.5 text-destructive" />
                Data Sensitivity Level
              </Label>
              <Select value={dataSensitivity} onChange={(e) => setDataSensitivity(e.target.value)}>
                <option value="1">1 - Public / Low Sensitivity</option>
                <option value="2">2 - Internal Operational</option>
                <option value="3">3 - Confidential / Business Data</option>
                <option value="4">4 - High / PII & Financial</option>
                <option value="5">5 - Critical / Secrets & Key Material</option>
              </Select>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label className="flex items-center gap-1.5 font-medium">
                <Globe className="h-3.5 w-3.5 text-accent" />
                Network Exposure
              </Label>
              <Select value={isPublicAccess ? "public" : "internal"} onChange={(e) => setIsPublicAccess(e.target.value === "public")}>
                <option value="public">Internet-Facing / Public APIs</option>
                <option value="internal">Internal Network / Isolated</option>
              </Select>
            </div>

            <div className="space-y-1.5">
              <Label className="font-medium">Crypto Agility</Label>
              <Select value={cryptoAgility} onChange={(e) => setCryptoAgility(e.target.value)}>
                <option value="1">1 - Hardcoded Primitives (Rigid)</option>
                <option value="2">2 - Modular Library (Moderate)</option>
                <option value="3">3 - Agile KMS / Dynamic Suites</option>
              </Select>
            </div>
          </div>
        </div>
      </Dialog>

      <div className="grid gap-4 xl:grid-cols-[0.85fr_1.4fr]">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <BrainCircuit className="h-4 w-4 text-primary" aria-hidden="true" />
              Start analysis
            </CardTitle>
            <p className="mt-1 text-xs leading-5 text-muted-foreground">
              Only completed scans are eligible for analysis. The current active scope is {info?.session_name || "All data"}.
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

              <div className="space-y-2">
                <Label htmlFor="max-findings">Maximum findings</Label>
                <Input
                  id="max-findings"
                  type="number"
                  min="1"
                  max={ANALYSIS_MAX_FINDINGS}
                  value={maxFindings}
                  onChange={(event) => setMaxFindings(event.target.value)}
                />
                <p className="text-[11px] text-muted-foreground">
                  1–{ANALYSIS_MAX_FINDINGS} findings per run. Raise the limit to widen coverage.
                </p>
              </div>

              <div className="flex gap-2">
                <Button
                  type="button"
                  variant="outline"
                  className="flex-1"
                  onClick={() => {
                    setTargetAwaitingItem(null);
                    setDialogOpen(true);
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
          <CardHeader className="flex-row items-center justify-between">
            <div>
              <CardTitle>Analysis runs</CardTitle>
              <p className="mt-1 text-xs text-muted-foreground">Analysis lifecycle: queued → running → completed, failed, or cancelled.</p>
            </div>
            <ClipboardList className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
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

function AnalysisRow({ run, selected, onSelect }: { run: AnalysisListItem; selected: boolean; onSelect: () => void }) {
  return <TableRow className={selected ? "bg-primary/5" : undefined}><TableCell><button type="button" onClick={onSelect} className="font-mono text-xs font-semibold hover:text-primary">#{run.id}</button><p className="mt-0.5 text-[11px] text-muted-foreground">{formatDate(run.created_at)}</p></TableCell><TableCell><p className="max-w-[250px] truncate text-sm">{run.target || "—"}</p></TableCell><TableCell><StatusBadge status={run.status} /></TableCell><TableCell><div className="flex min-w-28 items-center gap-2"><Progress value={run.progress} className="w-20" /><span className="tnum text-[11px] text-muted-foreground">{run.progress}%</span></div></TableCell><TableCell className="tnum">{formatNumber(run.assets)}</TableCell><TableCell><Button variant={selected ? "secondary" : "ghost"} size="sm" onClick={onSelect}>{selected ? "Selected" : "View"}</Button></TableCell></TableRow>;
}

function AnalysisDetailPanel({ run, loading, error, tab, onTabChange, onCancel, cancelling }: { run?: AnalysisDetail; loading: boolean; error?: string; tab: string; onTabChange: (value: string) => void; onCancel: () => void; cancelling: boolean }) {
  if (loading) return <Card><CardContent className="p-5"><LoadingState label="Loading analysis detail" /></CardContent></Card>;
  if (error) return <Card><CardContent className="p-5"><ErrorState message={error} /></CardContent></Card>;
  if (!run) return <Card><CardContent className="p-5"><EmptyState title="Analysis detail unavailable" description="The selected run is outside the active scope or has not returned data." /></CardContent></Card>;
  const summary = record(run.executive_summary);
  const summaryStats = record(summary.stats);
  const context = record(run.risk_context);
  const dataContext = record(context.data_context);
  const networkContext = record(context.network_context);
  const assessmentRows = array(run.assessments);
  return <Card><CardHeader className="flex-row items-start justify-between"><div><div className="flex flex-wrap items-center gap-2"><SectionLabel>Run #{run.id}</SectionLabel><StatusBadge status={run.status} /></div><p className="mt-2 max-w-2xl truncate text-sm text-muted-foreground" title={run.target}>{run.target || "No target reported"}</p><p className="mt-1 text-xs text-muted-foreground">Started {formatDate(run.started_at || run.created_at)}{run.finished_at ? ` · Finished ${formatDate(run.finished_at)}` : ""}</p></div><div className="flex items-center gap-2">{!isTerminalStatus(run.status) ? <Button variant="outline" size="sm" onClick={onCancel} disabled={cancelling}>{cancelling ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" /> : <XCircle className="h-3.5 w-3.5" aria-hidden="true" />}Cancel</Button> : null}</div></CardHeader><div className="border-b px-5 pt-4"><Progress value={run.progress} /><div className="flex justify-between py-2 text-[11px] text-muted-foreground"><span>{isTerminalStatus(run.status) ? "Terminal state" : "Refreshing analysis state"}</span><span className="tnum">{run.progress}%</span></div></div><div className="px-5 pt-3"><Tabs value={tab} onValueChange={onTabChange} items={[{ value: "summary", label: "Summary" }, { value: "assessments", label: "Assessments", count: assessmentRows.length }, { value: "cbom", label: "CBOM" }]} /></div><CardContent className="p-5"><div>{run.truncation?.truncated ? <div className="mb-5 flex gap-2 border border-warning/40 bg-warning/5 p-3 text-xs leading-5 text-warning"><AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" /><span>This analysis assessed {formatNumber(run.truncation.analysed)} of {formatNumber(run.truncation.available)} discovered findings{run.truncation.limit ? ` (limit ${formatNumber(run.truncation.limit)})` : ""}. Every result below describes only the assessed subset, not the whole scan.</span></div> : null}{run.error ? <div className="mb-5 flex gap-2 border border-destructive/30 bg-destructive/5 p-3 text-xs leading-5 text-destructive"><XCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />{run.error}</div> : null}{tab === "summary" ? <SummaryView run={run} summary={summary} summaryStats={summaryStats} dataContext={dataContext} networkContext={networkContext} /> : tab === "assessments" ? <AssessmentView assessments={assessmentRows} /> : <CbomView cbom={record(run.cbom)} runId={run.id} />}</div></CardContent></Card>;
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

  const modeVal = run.mode === "actual" || (run.target && !String(run.target).toLowerCase().startsWith("demo:")) ? "live" : "demo";
  const algoCatVal = summary.algorithm_category || (rows[0]?.algorithm_category ? titleCase(rows[0].algorithm_category) : "PUBLIC_KEY");

  return (
    <div className="space-y-6">
      <div className="grid gap-3 sm:grid-cols-4">
        <SummaryMetric label="Findings processed" value={run.findings_count} />
        <SummaryMetric label="Summary assets" value={summaryStats.assets ?? rows.length} />
        <SummaryMetric label="Algorithm category" value={algoCatVal} />
        <SummaryMetric label="Analysis mode" value={modeVal} />
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
