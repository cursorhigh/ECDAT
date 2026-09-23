"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, ArrowRight, CheckCircle2, ClipboardCheck, Loader2, Map, RefreshCw, Route, Shield, XCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState, ErrorState, LoadingState } from "@/components/feedback/data-state";
import { PageHeader, SectionLabel } from "@/components/data/page-header";
import { StatusBadge, riskBadge } from "@/components/data/status-badge";
import { useToast } from "@/components/feedback/toast";
import { api } from "@/lib/api/client";
import type { JsonRecord, MitigationPlan } from "@/lib/api/types";
import { useSession } from "@/lib/session-context";
import { formatDate, formatNumber, isTerminalStatus, titleCase, truncate } from "@/lib/utils";

const terminalStatuses = new Set(["complete", "completed", "failed", "cancelled", "canceled"]);

function record(value: unknown): JsonRecord {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as JsonRecord) : {};
}

function array(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function text(value: unknown) {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

export default function MitigationPage() {
  const { ready, scopeKey, info } = useSession();
  const { pushToast } = useToast();
  const queryClient = useQueryClient();
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const overview = useQuery({ queryKey: ["mitigation-overview", scopeKey], queryFn: api.mitigationOverview, enabled: ready });
  const plans = useQuery({ queryKey: ["mitigation-plans", scopeKey], queryFn: api.mitigationList, enabled: ready });
  const runs = useQuery({ queryKey: ["mitigation-runs", scopeKey], queryFn: api.analysisList, enabled: ready });
  const defaultPlanId = plans.data?.[0]?.id || null;
  const activePlanId = selectedId || defaultPlanId;
  const detail = useQuery({ queryKey: ["mitigation-detail", activePlanId, scopeKey], queryFn: () => api.mitigation(activePlanId!), enabled: Boolean(activePlanId), refetchInterval: (query) => terminalStatuses.has(String(query.state.data?.status || "").toLowerCase()) ? false : 3000 });

  const generate = useMutation({
    mutationFn: (runId: number) => api.generateMitigation(runId),
    onSuccess: async (plan) => { setSelectedId(plan.id); pushToast(`Mitigation plan #${plan.id} is ${titleCase(plan.status)}.`, "success"); await queryClient.invalidateQueries({ queryKey: ["mitigation"] }); },
    onError: (error) => pushToast(error instanceof Error ? error.message : "Mitigation plan could not be generated.", "error")
  });

  const cancel = useMutation({
    mutationFn: (id: number) => api.cancelMitigation(id),
    onSuccess: async () => { pushToast("Mitigation cancellation requested.", "info"); await queryClient.invalidateQueries({ queryKey: ["mitigation"] }); },
    onError: (error) => pushToast(error instanceof Error ? error.message : "Plan could not be cancelled.", "error")
  });

  const refresh = () => { void overview.refetch(); void plans.refetch(); void runs.refetch(); if (activePlanId) void detail.refetch(); };
  const totals = overview.data?.totals;
  const unguarded = overview.data?.runs_unguarded || [];
  const selectedPlan = detail.data;

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Planning segment" title="Mitigation & migration" description="Turn completed analysis into a backend-generated plan, then inspect urgency, blast radius, effort, and per-asset migration direction." actions={<Button variant="outline" size="sm" onClick={refresh}><RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />Refresh</Button>} />
      {overview.isLoading ? <LoadingState label="Loading remediation posture" /> : overview.isError ? <ErrorState message={overview.error instanceof Error ? overview.error.message : undefined} onRetry={() => void overview.refetch()} /> : <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5"><PlanMetric label="Plans" value={totals?.plans} icon={ClipboardCheck} /><PlanMetric label="Assets covered" value={totals?.assets} icon={Shield} /><PlanMetric label="Urgent" value={totals?.urgent} icon={AlertTriangle} tone="danger" /><PlanMetric label="Quantum-vulnerable" value={totals?.quantum_vulnerable} icon={Route} tone="warning" /><PlanMetric label="HNDL exposed" value={totals?.hndl_exposed} icon={AlertTriangle} tone="danger" /></div>}

      <div className="grid gap-4 xl:grid-cols-[1.25fr_0.75fr]"><Card><CardHeader className="flex-row items-center justify-between"><div><CardTitle>Mitigation plans</CardTitle><p className="mt-1 text-xs text-muted-foreground">Plans are scoped to {info?.session_name || "All data"}.</p></div><Route className="h-4 w-4 text-muted-foreground" aria-hidden="true" /></CardHeader><CardContent className="p-0">{plans.isLoading ? <div className="p-5"><LoadingState label="Loading mitigation plans" /></div> : plans.isError ? <div className="p-5"><ErrorState message={plans.error instanceof Error ? plans.error.message : undefined} onRetry={() => void plans.refetch()} /></div> : plans.data?.length ? <Table><TableHeader><TableRow><TableHead>Plan</TableHead><TableHead>Target</TableHead><TableHead>Status</TableHead><TableHead>Progress</TableHead><TableHead>Urgent</TableHead><TableHead /></TableRow></TableHeader><TableBody>{plans.data.map((plan) => <PlanRow key={plan.id} plan={plan} selected={plan.id === activePlanId} onSelect={() => setSelectedId(plan.id)} />)}</TableBody></Table> : <div className="p-5"><EmptyState title="No mitigation plans" description="Generate a plan from a completed analysis run." /></div>}</CardContent></Card><Card><CardHeader><CardTitle className="flex items-center gap-2"><ArrowRight className="h-4 w-4 text-primary" aria-hidden="true" />Runs awaiting a plan</CardTitle><p className="mt-1 text-xs text-muted-foreground">Completed analysis runs reported by the backend without a mitigation plan.</p></CardHeader><CardContent className="p-0">{unguarded.length ? <div className="divide-y">{unguarded.map((run) => <div key={run.id} className="flex items-center gap-3 px-5 py-3"><div className="min-w-0 flex-1"><p className="truncate text-sm font-medium">{run.target || `Run #${run.id}`}</p><p className="mt-0.5 text-[11px] text-muted-foreground">Run #{run.id} · {formatNumber(run.assets)} assets · {formatDate(run.created_at)}</p></div><Button size="sm" variant="outline" onClick={() => generate.mutate(run.id)} disabled={generate.isPending}><Route className="h-3.5 w-3.5" aria-hidden="true" />Generate</Button></div>)}</div> : <div className="p-5"><EmptyState title="Nothing waiting" description="Every completed run in scope currently has a plan." /></div>}</CardContent></Card></div>

      {activePlanId ? <PlanDetail plan={selectedPlan} loading={detail.isLoading} error={detail.error instanceof Error ? detail.error.message : undefined} onCancel={() => cancel.mutate(activePlanId)} cancelling={cancel.isPending} /> : <Card><CardContent className="p-5"><EmptyState title="Select a plan" description="Choose a mitigation plan to inspect its backend document." /></CardContent></Card>}
      {runs.isLoading ? null : <Card><CardHeader><CardTitle>Generate from analysis</CardTitle><p className="mt-1 text-xs text-muted-foreground">Only completed analysis runs are accepted. The backend creates or resumes the run’s single plan.</p></CardHeader><CardContent className="p-0">{runs.data?.filter((run) => run.status === "completed").length ? <Table><TableHeader><TableRow><TableHead>Run</TableHead><TableHead>Target</TableHead><TableHead>Assets</TableHead><TableHead>Created</TableHead><TableHead /></TableRow></TableHeader><TableBody>{runs.data.filter((run) => run.status === "completed").map((run) => <TableRow key={run.id}><TableCell className="font-mono text-xs">#{run.id}</TableCell><TableCell className="max-w-[320px] truncate">{run.target || "—"}</TableCell><TableCell className="tnum">{formatNumber(run.assets)}</TableCell><TableCell className="text-xs text-muted-foreground">{formatDate(run.created_at)}</TableCell><TableCell><Button variant="outline" size="sm" onClick={() => generate.mutate(run.id)} disabled={generate.isPending}><Route className="h-3.5 w-3.5" aria-hidden="true" />Generate plan</Button></TableCell></TableRow>)}</TableBody></Table> : <div className="p-5"><EmptyState title="No completed analysis runs" description="Run risk analysis first to make a mitigation plan available." /></div>}</CardContent></Card>}
    </div>
  );
}

function PlanMetric({ label, value, icon: Icon, tone = "default" }: { label: string; value?: number; icon: typeof Route; tone?: "default" | "danger" | "warning" }) {
  return <Card className={`p-4 ${tone === "danger" ? "border-destructive/35" : tone === "warning" ? "border-warning/35" : ""}`}><div className="flex items-center justify-between"><p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{label}</p><Icon className={`h-4 w-4 ${tone === "danger" ? "text-destructive" : tone === "warning" ? "text-warning" : "text-primary"}`} aria-hidden="true" /></div><p className="tnum mt-3 text-2xl font-semibold">{formatNumber(value)}</p></Card>;
}

function PlanRow({ plan, selected, onSelect }: { plan: MitigationPlan; selected: boolean; onSelect: () => void }) {
  return <TableRow className={selected ? "bg-primary/5" : undefined}><TableCell><button type="button" onClick={onSelect} className="font-mono text-xs font-semibold hover:text-primary">#{plan.id}</button><p className="mt-0.5 text-[11px] text-muted-foreground">Run #{plan.run_id}</p></TableCell><TableCell><p className="max-w-[240px] truncate text-sm">{plan.target || "—"}</p></TableCell><TableCell><StatusBadge status={plan.status} /></TableCell><TableCell><div className="flex min-w-28 items-center gap-2"><Progress value={plan.progress} className="w-20" /><span className="tnum text-[11px] text-muted-foreground">{plan.progress}%</span></div></TableCell><TableCell className="tnum">{formatNumber(plan.summary?.urgent)}</TableCell><TableCell><Button variant={selected ? "secondary" : "ghost"} size="sm" onClick={onSelect}>{selected ? "Selected" : "View"}</Button></TableCell></TableRow>;
}

function PlanDetail({ plan, loading, error, onCancel, cancelling }: { plan?: MitigationPlan; loading: boolean; error?: string; onCancel: () => void; cancelling: boolean }) {
  if (loading) return <Card><CardContent className="p-5"><LoadingState label="Loading mitigation plan" /></CardContent></Card>;
  if (error) return <Card><CardContent className="p-5"><ErrorState message={error} /></CardContent></Card>;
  if (!plan) return <Card><CardContent className="p-5"><EmptyState title="Plan unavailable" description="The selected plan is outside the active scope." /></CardContent></Card>;
  const document = record(plan.document);
  const blast = record(document.blast_radius);
  const rows = array(document.rows);
  const waves = array(document.waves);
  const recommendations = array(document.recommendations);
  return <Card><CardHeader className="flex-row items-start justify-between"><div><div className="flex items-center gap-2"><SectionLabel>Plan #{plan.id}</SectionLabel><StatusBadge status={plan.status} /></div><p className="mt-2 max-w-2xl truncate text-sm text-muted-foreground">{plan.target || "No target reported"}</p><p className="mt-1 text-xs text-muted-foreground">Run #{plan.run_id} · Created {formatDate(plan.created_at)}</p></div>{!isTerminalStatus(plan.status) ? <Button variant="outline" size="sm" onClick={onCancel} disabled={cancelling}>{cancelling ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" /> : <XCircle className="h-3.5 w-3.5" aria-hidden="true" />}Cancel</Button> : null}</CardHeader><div className="border-b px-5 pt-4"><Progress value={plan.progress} /><div className="flex justify-between py-2 text-[11px] text-muted-foreground"><span>{isTerminalStatus(plan.status) ? "Terminal state" : "Polling backend state"}</span><span className="tnum">{plan.progress}%</span></div></div><CardContent className="space-y-6 p-5">{plan.error ? <div className="flex gap-2 border border-destructive/30 bg-destructive/5 p-3 text-xs leading-5 text-destructive"><XCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />{plan.error}</div> : null}<div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5"><PlanMetric label="Assets" value={plan.summary?.assets} icon={Shield} /><PlanMetric label="Urgent" value={plan.summary?.urgent} icon={AlertTriangle} tone="danger" /><PlanMetric label="Quantum-vulnerable" value={plan.summary?.quantum_vulnerable} icon={Route} tone="warning" /><PlanMetric label="HNDL exposed" value={plan.summary?.hndl_exposed} icon={AlertTriangle} tone="danger" /><PlanMetric label="Blast severity" value={plan.summary?.blast_severity ? 1 : 0} icon={Map} /></div><div className="grid gap-4 lg:grid-cols-2"><div className="border bg-muted/20 p-4"><SectionLabel>Executive summary</SectionLabel><p className="mt-3 text-sm leading-6">{text(document.executive_summary || document.quantum_risk_narrative || "No narrative returned.")}</p></div><div className="border bg-muted/20 p-4"><SectionLabel>Blast radius and effort</SectionLabel><div className="mt-3 space-y-2 text-xs"><div className="flex justify-between gap-4"><span className="text-muted-foreground">Severity</span><span>{titleCase(blast.severity || plan.summary?.blast_severity)}</span></div><div className="flex justify-between gap-4"><span className="text-muted-foreground">Effort estimate</span><span>{plan.summary?.effort_estimate_quarters ? `${plan.summary.effort_estimate_quarters} quarters` : "—"}</span></div><div className="flex justify-between gap-4"><span className="text-muted-foreground">Services</span><span>{text(blast.services || blast.services_affected || "—")}</span></div></div></div></div><div><SectionLabel>Asset remediation rows</SectionLabel>{rows.length ? <div className="mt-3 overflow-x-auto border"><Table><TableHeader><TableRow><TableHead>Asset</TableHead><TableHead>Risk</TableHead><TableHead>Priority</TableHead><TableHead>Replacement</TableHead><TableHead>Action</TableHead></TableRow></TableHeader><TableBody>{rows.map((value, index) => { const row = record(value); return <TableRow key={String(row.asset_id || index)}><TableCell className="max-w-[220px] truncate font-mono text-xs">{text(row.asset_id || row.name)}</TableCell><TableCell>{riskBadge(row.risk || row.overall_risk)}</TableCell><TableCell>{riskBadge(row.priority || row.migration_priority)}</TableCell><TableCell className="max-w-[220px] text-xs text-muted-foreground">{text(row.replacement || row.migration_replacement)}</TableCell><TableCell className="max-w-[280px] text-xs text-muted-foreground">{text(row.recommended_action || row.action)}</TableCell></TableRow>; })}</TableBody></Table></div> : <div className="mt-3"><EmptyState title="No remediation rows" description="The plan document does not include a rows array." /></div>}</div><div className="grid gap-4 lg:grid-cols-2"><div><SectionLabel>Migration waves</SectionLabel>{waves.length ? <div className="mt-3 space-y-2">{waves.map((value, index) => { const wave = record(value); return <div key={index} className="flex items-center justify-between border p-3 text-sm"><span className="font-medium">Wave {index + 1}</span><span className="text-xs text-muted-foreground">{text(wave.name || wave.description || `${wave.asset_ids?.toString?.() || ""}`)}</span></div>; })}</div> : <p className="mt-3 text-xs text-muted-foreground">No waves returned.</p>}</div><div><SectionLabel>Recommendations</SectionLabel>{recommendations.length ? <ul className="mt-3 space-y-2 text-xs leading-5 text-muted-foreground">{recommendations.map((value, index) => <li key={index} className="border-l-2 border-primary/50 pl-3">{text(value)}</li>)}</ul> : <p className="mt-3 text-xs text-muted-foreground">No recommendations returned.</p>}</div></div></CardContent></Card>;
}
