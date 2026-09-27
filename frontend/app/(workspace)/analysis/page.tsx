"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, BrainCircuit, CheckCircle2, ClipboardList, Loader2, Play, XCircle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { RefreshButton } from "@/components/ui/refresh-button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label, Select, Textarea } from "@/components/ui/input";
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

function displayValue(value: unknown) {  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

/** Server-side cap on findings per analysis run. */
const ANALYSIS_MAX_FINDINGS = 500;

export default function AnalysisPage() {
  const { ready, scopeKey, info , hasSession } = useSession();
  const { pushToast } = useToast();
  const queryClient = useQueryClient();
  const [scanJob, setScanJob] = useState("");
  const [maxFindings, setMaxFindings] = useState(String(ANALYSIS_MAX_FINDINGS));
  const [context, setContext] = useState("");
  const [selectedRunId, setSelectedRunId] = useState<number | null>(null);
  const [detailTab, setDetailTab] = useState("summary");

  const runs = useQuery({ queryKey: ["analysis-runs", scopeKey], queryFn: api.analysisList, enabled: ready && hasSession });
  // Keyed under the shared "scans" prefix so the Scans page's invalidations
  // reach this query, but with the ordering included so pages requesting a
  // different order never read each other's cached payload.
  const scans = useQuery({ queryKey: ["scans", scopeKey, "created_at"], queryFn: () => api.scans({ ordering: "created_at", page: 1 }), enabled: ready && hasSession });
  const awaiting = useQuery({ queryKey: ["analysis-awaiting", scopeKey], queryFn: api.analysisAwaiting, enabled: ready && hasSession, refetchInterval: 10000 });
  const defaultRunId = runs.data?.find((run) => run.status === "completed")?.id || runs.data?.[0]?.id || null;
  const activeRunId = selectedRunId || defaultRunId;
  const detail = useQuery({ queryKey: ["analysis-detail", activeRunId, scopeKey], queryFn: () => api.analysis(activeRunId!), enabled: Boolean(activeRunId), refetchInterval: (query) => terminalStatuses.has(String(query.state.data?.status || "").toLowerCase()) ? false : 3000 });

  const start = useMutation({
    mutationFn: () => {
      if (!scanJob) throw new Error("Choose a completed scan first.");
      let rawContext: string | JsonRecord | undefined;
      if (context.trim()) {
        try { rawContext = JSON.parse(context); } catch { rawContext = context.trim(); }
      }
      return api.startAnalysis({ scan_job: Number(scanJob), max_findings: Number(maxFindings) || undefined, raw_system_context: rawContext });
    },
    onSuccess: async (created) => {
      setSelectedRunId(created.id);
      setContext("");
      pushToast(`Analysis run #${created.id} is ${titleCase(created.status)}.`, "success");
      await queryClient.invalidateQueries({ queryKey: ["analysis-runs"] });
    },
    onError: (error) => pushToast(error instanceof Error ? error.message : "Analysis could not be started.", "error")
  });

  const resolve = useMutation({
    mutationFn: async (item: AwaitingAnalysis) => {
      let rawContext: string | JsonRecord | undefined;
      if (context.trim()) {
        try { rawContext = JSON.parse(context); } catch { rawContext = context.trim(); }
      }
      return api.startAnalysis({ scan_job: item.scan_job_id, raw_system_context: rawContext });
    },
    onSuccess: async (created) => { setSelectedRunId(created.id); setContext(""); pushToast(`Context committed to run #${created.id}.`, "success"); await queryClient.invalidateQueries({ queryKey: ["analysis-awaiting"] }); await queryClient.invalidateQueries({ queryKey: ["analysis-runs"] }); },
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
  // A partial scan succeeded but skipped sources, so it is not analysable.
  // It is shown, not hidden, so the gap is visible rather than silent.
  const partialScans = (scans.data?.results || []).filter((scan) => scan.status === "partial");
  const awaitingRows = awaiting.data || [];

  return (
    <div className="space-y-6">
      <PageHeader compact eyebrow="Analysis segment" title="Risk analysis" description="Start or resume analysis runs, resolve context decisions, and inspect risk assessments, migration priority, and CBOM output." actions={<RefreshButton onRefresh={refresh} />} />

      {awaitingRows.length ? <Card className="border-warning/40 bg-warning/5"><CardContent className="p-4"><div className="flex items-start gap-3"><AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-warning" aria-hidden="true" /><div className="min-w-0 flex-1"><h2 className="text-sm font-semibold">Context decision required</h2><p className="mt-1 text-xs leading-5 text-muted-foreground">The analysis paused {awaitingRows.length === 1 ? "an analysis" : "analyses"} before execution. Commit context to the existing run; starting again will not create a duplicate.</p><div className="mt-3 flex flex-wrap items-end gap-2"><div className="min-w-[240px] flex-1 space-y-2"><Label htmlFor="awaiting-context">Optional system context</Label><Textarea id="awaiting-context" value={context} onChange={(event) => setContext(event.target.value)} placeholder="Paste JSON context or a plain-text note" className="min-h-20 font-mono text-xs" /></div><Button onClick={() => void resolve.mutate(awaitingRows[0])} disabled={resolve.isPending}>{resolve.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" /> : <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />}Commit context</Button></div></div></div></CardContent></Card> : null}

      <div className="grid gap-4 xl:grid-cols-[0.85fr_1.4fr]">
        <Card><CardHeader><CardTitle className="flex items-center gap-2"><BrainCircuit className="h-4 w-4 text-primary" aria-hidden="true" />Start analysis</CardTitle><p className="mt-1 text-xs leading-5 text-muted-foreground">Only completed scans are eligible for analysis. The current active scope is {info?.session_name || "All data"}.</p></CardHeader><CardContent><div className="space-y-4"><div className="space-y-2"><Label htmlFor="analysis-scan">Completed scan</Label><Select id="analysis-scan" value={scanJob} onChange={(event) => setScanJob(event.target.value)}><option value="">Select a scan</option>{completedScans.map((scan) => <option key={scan.id} value={scan.id}>#{scan.id} · {truncate(scan.target || "Scan", 38)}</option>)}</Select>{!completedScans.length ? <p className="text-[11px] text-muted-foreground">{partialScans.length ? `No fully completed scans are available. ${partialScans.length} partial scan${partialScans.length === 1 ? " is" : "s are"} excluded — analysis needs complete coverage.` : "No completed scans are available in this scope."}</p> : null}{partialScans.length ? <ul className="mt-2 space-y-1">{partialScans.map((scan) => <li key={scan.id} className="text-[11px] text-muted-foreground"><span className="font-mono">#{scan.id}</span> · {truncate(scan.target || "Scan", 34)} · <span className="text-warning">Partial</span> — {scan.items_skipped || 0} item(s) skipped during discovery</li>)}</ul> : null}</div><div className="space-y-2"><Label htmlFor="max-findings">Maximum findings</Label><Input id="max-findings" type="number" min="1" max={ANALYSIS_MAX_FINDINGS} value={maxFindings} onChange={(event) => setMaxFindings(event.target.value)} /><p className="text-[11px] text-muted-foreground">1–{ANALYSIS_MAX_FINDINGS} findings per run. Raise the limit to widen coverage; if the cap is reached, the result states how many were left out.</p></div><div className="space-y-2"><Label htmlFor="analysis-context">Optional system context</Label><Textarea id="analysis-context" value={context} onChange={(event) => setContext(event.target.value)} placeholder="JSON or a plain-text note" className="min-h-28 font-mono text-xs" /><p className="text-[11px] leading-4 text-muted-foreground">The analysis may pause an auto-started run and request additional context.</p></div><Button className="w-full" onClick={() => start.mutate()} disabled={start.isPending || !scanJob}>{start.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" /> : <Play className="h-3.5 w-3.5" aria-hidden="true" />}Start or resume analysis</Button></div></CardContent></Card>
        <Card><CardHeader className="flex-row items-center justify-between"><div><CardTitle>Analysis runs</CardTitle><p className="mt-1 text-xs text-muted-foreground">Analysis lifecycle: queued → running → completed, failed, or cancelled.</p></div><ClipboardList className="h-4 w-4 text-muted-foreground" aria-hidden="true" /></CardHeader><CardContent className="p-0">{runs.isLoading ? <div className="p-5"><LoadingState label="Loading analysis runs" /></div> : runs.isError ? <div className="p-5"><ErrorState message={runs.error instanceof Error ? runs.error.message : undefined} onRetry={() => void runs.refetch()} /></div> : runs.data?.length ? <Table><TableHeader><TableRow><TableHead>Run</TableHead><TableHead>Target</TableHead><TableHead>Status</TableHead><TableHead>Progress</TableHead><TableHead>Assets</TableHead><TableHead /></TableRow></TableHeader><TableBody>{runs.data.map((run) => <AnalysisRow key={run.id} run={run} selected={run.id === activeRunId} onSelect={() => { setSelectedRunId(run.id); setDetailTab("summary"); }} />)}</TableBody></Table> : <div className="p-5"><EmptyState title="No analysis runs" description="Start analysis from a completed scan to create the first run." /></div>}</CardContent></Card>
      </div>

      {activeRunId ? <AnalysisDetailPanel run={detail.data} loading={detail.isLoading} error={detail.error instanceof Error ? detail.error.message : undefined} tab={detailTab} onTabChange={setDetailTab} onCancel={() => cancel.mutate(activeRunId)} cancelling={cancel.isPending} /> : <Card><CardContent className="p-5"><EmptyState title="Select an analysis run" description="Choose a run above to inspect its summary and assessments." /></CardContent></Card>}
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
  return <div className="space-y-6"><div className="grid gap-3 sm:grid-cols-4"><SummaryMetric label="Findings processed" value={run.findings_count} /><SummaryMetric label="Summary assets" value={summaryStats.assets ?? rows.length} /><SummaryMetric label="Algorithm category" value={displayValue(summary.algorithm_category)} /><SummaryMetric label="Analysis mode" value={displayValue(run.mode)} /></div><div className="grid gap-4 lg:grid-cols-2"><div className="border bg-muted/20 p-4"><SectionLabel>Risk context</SectionLabel><div className="mt-3 space-y-2 text-xs"><div className="flex justify-between gap-4"><span className="text-muted-foreground">Data sensitivity</span><span>{displayValue(dataContext.sensitivity)}</span></div><div className="flex justify-between gap-4"><span className="text-muted-foreground">Data lifetime</span><span>{displayValue(dataContext.data_lifetime_years)}</span></div><div className="flex justify-between gap-4"><span className="text-muted-foreground">Internet exposed</span><span>{displayValue(networkContext.internet_exposed)}</span></div><div className="flex justify-between gap-4"><span className="text-muted-foreground">Collectable</span><span>{displayValue(networkContext.collectable)}</span></div></div></div><div className="border bg-muted/20 p-4"><SectionLabel>Executive summary</SectionLabel><div className="mt-3 grid gap-3 sm:grid-cols-4"><SummaryMetric label="Assets assessed" value={formatNumber(num(summaryStats.assets))} /><SummaryMetric label="Urgent" value={formatNumber(num(summaryStats.urgent))} tone="danger" /><SummaryMetric label="Critical" value={formatNumber(num(summaryStats.critical))} tone="danger" /><SummaryMetric label="HNDL applicable" value={formatNumber(num(summaryStats.hndl_applicable))} tone="warning" /></div>{narrative ? <p className="mt-3 text-sm leading-6">{narrative}</p> : <p className="mt-3 text-xs text-muted-foreground">This run reports structured results only; no written narrative was returned.</p>}</div></div><div><div className="mb-3 flex items-center justify-between"><SectionLabel>Summary rows</SectionLabel><span className="text-[11px] text-muted-foreground">Sorted by migration priority</span></div>{rows.length ? <div className="overflow-x-auto border"><Table><TableHeader><TableRow><TableHead>Asset</TableHead><TableHead>Category</TableHead><TableHead>Overall risk</TableHead><TableHead>Migration priority</TableHead><TableHead>Quantum</TableHead></TableRow></TableHeader><TableBody>{rows.map((row, index) => <TableRow key={`${row.asset_id}-${index}`}><TableCell className="font-mono text-xs">{displayValue(row.asset_id)}</TableCell><TableCell className="text-xs">{titleCase(row.algorithm_category)}</TableCell><TableCell>{riskBadge(row.overall_risk)}</TableCell><TableCell>{riskBadge(row.migration_priority)}</TableCell><TableCell>{row.quantum_vulnerable ? <Badge variant="danger">Yes</Badge> : <Badge>No</Badge>}</TableCell></TableRow>)}</TableBody></Table></div> : <EmptyState title="No summary rows" description="The run completed without returning summary rows." />}</div></div>;
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
