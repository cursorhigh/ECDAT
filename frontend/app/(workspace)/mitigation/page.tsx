"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertCircle, AlertTriangle, ArrowRight, Clock3, GitBranch, Loader2, Map, Route, Shield, ShieldAlert, ShieldCheck, XCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { RefreshButton } from "@/components/ui/refresh-button";
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
import { cn, formatDate, formatNumber, isTerminalStatus, refetchAllOrThrow, titleCase } from "@/lib/utils";

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

/** The replacement lives inside migration_impact on the plan row. */
function replacementOf(row: JsonRecord) {
  const impact = record(row.migration_impact);
  return impact.replacement || row.replacement || row.migration_replacement;
}

export default function MitigationPage() {
  const { ready, scopeKey, info , hasSession } = useSession();
  const { pushToast } = useToast();
  const queryClient = useQueryClient();
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const overview = useQuery({ queryKey: ["mitigation-overview", scopeKey], queryFn: api.mitigationOverview, enabled: ready && hasSession });
  const plans = useQuery({ queryKey: ["mitigation-plans", scopeKey], queryFn: api.mitigationList, enabled: ready && hasSession });
  const defaultPlanId = plans.data?.[0]?.id || null;
  const activePlanId = selectedId || defaultPlanId;
  const detail = useQuery({ queryKey: ["mitigation-detail", activePlanId, scopeKey], queryFn: () => api.mitigation(activePlanId!), enabled: Boolean(activePlanId), refetchInterval: (query) => terminalStatuses.has(String(query.state.data?.status || "").toLowerCase()) ? false : 3000 });

  const cancel = useMutation({
    mutationFn: (id: number) => api.cancelMitigation(id),
    onSuccess: async () => { pushToast("Mitigation cancellation requested.", "info"); await queryClient.invalidateQueries({ queryKey: ["mitigation"] }); },
    onError: (error) => pushToast(error instanceof Error ? error.message : "Plan could not be cancelled.", "error")
  });

  const refresh = async () => {
    await refetchAllOrThrow([overview, plans]);
    if (activePlanId) await refetchAllOrThrow([detail]);
  };
  const totals = overview.data?.totals;
  const unguarded = overview.data?.runs_unguarded || [];
  const selectedPlan = detail.data;

  return (
    <div className="space-y-6">
      <PageHeader compact eyebrow="Planning segment" title="Mitigation & migration" description="Turn completed analysis into a structured migration plan, then inspect urgency, blast radius, effort, and per-asset migration direction." actions={<RefreshButton onRefresh={refresh} />} />
      
      <div className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <SectionLabel>Quantum Migration Timelines &amp; Posture</SectionLabel>
          <div className="flex items-center gap-2 rounded-full border bg-muted/40 px-3 py-1 text-xs text-muted-foreground">
            <Clock3 className="h-3.5 w-3.5 text-primary" aria-hidden="true" />
            <span>Average Quantum Transition Time: <strong className="text-foreground font-semibold">12–18 Months (~5–6 Quarters)</strong></span>
          </div>
        </div>

        {overview.isLoading ? (
          <LoadingState label="Loading remediation posture" />
        ) : overview.isError ? (
          <ErrorState message={overview.error instanceof Error ? overview.error.message : undefined} onRetry={() => void overview.refetch()} />
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
            <PlanMetric label="Urgent" value={totals?.urgent} subtext="0–3 Mos" icon={AlertTriangle} tone="purple" />
            <PlanMetric label="High" value={totals?.high} subtext="3–12 Mos" icon={ShieldAlert} tone="danger" />
            <PlanMetric label="Medium" value={totals?.medium} subtext="12–24 Mos" icon={AlertCircle} tone="warning" />
            <PlanMetric label="Low" value={totals?.low} subtext="24+ Mos" icon={ShieldCheck} tone="success" />
            <PlanMetric label="HNDL exposure" value={totals?.hndl_exposed} subtext="Immediate" icon={AlertTriangle} tone="orange" />
            <PlanMetric label="Quantum vulnerable" value={totals?.quantum_vulnerable} subtext="Target 2033" icon={Route} tone="warning" />
          </div>
        )}
      </div>

      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <div>
            <CardTitle>Mitigation plans</CardTitle>
            <p className="mt-1 text-xs text-muted-foreground">Plans are scoped to {info?.session_name || "All data"}.</p>
          </div>
          <Route className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
        </CardHeader>
        <CardContent className="p-0">
          {plans.isLoading ? (
            <div className="p-5"><LoadingState label="Loading mitigation plans" /></div>
          ) : plans.isError ? (
            <div className="p-5"><ErrorState message={plans.error instanceof Error ? plans.error.message : undefined} onRetry={() => void plans.refetch()} /></div>
          ) : plans.data?.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Plan</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Progress</TableHead>
                  <TableHead>Urgent</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {plans.data.map((plan) => (
                  <PlanRow key={plan.id} plan={plan} selected={plan.id === activePlanId} onSelect={() => setSelectedId(plan.id)} />
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="p-5"><EmptyState title="No mitigation plans" description="Generate a plan from a completed analysis run." /></div>
          )}
        </CardContent>
      </Card>

      {activePlanId ? <PlanDetail plan={selectedPlan} loading={detail.isLoading} error={detail.error instanceof Error ? detail.error.message : undefined} onCancel={() => cancel.mutate(activePlanId)} cancelling={cancel.isPending} /> : <Card><CardContent className="p-5"><EmptyState title="Select a plan" description="Choose a mitigation plan to inspect its plan document." /></CardContent></Card>}
    </div>
  );
}

function PlanMetric({ label, value, display, subtext, icon: Icon, tone = "default" }: { label: string; value?: number; display?: string; subtext?: string; icon: typeof Route; tone?: "default" | "danger" | "warning" | "info" | "success" | "purple" | "orange" }) {
  const borderClass =
    tone === "purple"
      ? "border-purple-500/35"
      : tone === "orange"
      ? "border-orange-500/35"
      : tone === "danger"
      ? "border-destructive/35"
      : tone === "warning"
      ? "border-amber-500/35"
      : tone === "info"
      ? "border-blue-500/35"
      : tone === "success"
      ? "border-emerald-500/35"
      : "";

  const iconClass =
    tone === "purple"
      ? "text-purple-500"
      : tone === "orange"
      ? "text-orange-500"
      : tone === "danger"
      ? "text-destructive"
      : tone === "warning"
      ? "text-amber-500"
      : tone === "info"
      ? "text-blue-400"
      : tone === "success"
      ? "text-emerald-500"
      : "text-primary";

  return (
    <Card className={`p-4 ${borderClass} flex flex-col justify-between`}>
      <div className="flex items-center justify-between">
        <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{label}</p>
        <Icon className={`h-4 w-4 ${iconClass}`} aria-hidden="true" />
      </div>
      <div className="mt-3 flex items-baseline justify-between gap-2">
        <p className="tnum truncate text-2xl font-semibold" title={display}>{display ?? formatNumber(value)}</p>
        {subtext ? (
          <span className="text-[10px] font-mono font-medium text-muted-foreground whitespace-nowrap bg-muted/60 px-1.5 py-0.5 rounded border border-border/40">
            {subtext}
          </span>
        ) : null}
      </div>
    </Card>
  );
}

function PlanRow({ plan, selected, onSelect }: { plan: MitigationPlan; selected: boolean; onSelect: () => void }) {
  return <TableRow className={selected ? "bg-primary/5" : undefined}><TableCell><button type="button" onClick={onSelect} className="font-mono text-xs font-semibold hover:text-primary">#{plan.id}</button><p className="mt-0.5 text-[11px] text-muted-foreground">Run #{plan.run_id}</p></TableCell><TableCell><p className="max-w-[240px] truncate text-sm">{plan.target || "—"}</p></TableCell><TableCell><StatusBadge status={plan.status} /></TableCell><TableCell><div className="flex min-w-28 items-center gap-2"><Progress value={plan.progress} className="w-20" /><span className="tnum text-[11px] text-muted-foreground">{plan.progress}%</span></div></TableCell><TableCell className="tnum">{formatNumber(plan.summary?.urgent)}</TableCell><TableCell><Button variant={selected ? "secondary" : "ghost"} size="sm" onClick={onSelect}>{selected ? "Selected" : "View"}</Button></TableCell></TableRow>;
}

function PlanDetail({ plan, loading, error, onCancel, cancelling }: { plan?: MitigationPlan; loading: boolean; error?: string; onCancel: () => void; cancelling: boolean }) {
  const [hoveredWave, setHoveredWave] = useState<number | null>(null);

  if (loading) return <Card><CardContent className="p-5"><LoadingState label="Loading mitigation plan" /></CardContent></Card>;
  if (error) return <Card><CardContent className="p-5"><ErrorState message={error} /></CardContent></Card>;
  if (!plan) return <Card><CardContent className="p-5"><EmptyState title="Plan unavailable" description="This plan could not be loaded for the current scope." /></CardContent></Card>;
  const document = record(plan.document);
  const blast = record(document.blast_radius);
  const rows = array(document.rows);
  const waves = array(document.waves);
  const recommendations = array(document.recommendations);

  const parseWaveNum = (waveObj: JsonRecord, index: number): number => {
    if (typeof waveObj.wave === "number") return waveObj.wave;
    if (typeof waveObj.wave_number === "number") return waveObj.wave_number;
    const match = String(waveObj.name || "").match(/Wave\s*(\d+)/i);
    if (match) return parseInt(match[1], 10);
    return index + 1;
  };

  const parseRecWaveNum = (recObj: JsonRecord): number | null => {
    if (typeof recObj.wave === "number") return recObj.wave;
    if (typeof recObj.wave_number === "number") return recObj.wave_number;
    const match = String(recObj.wave || "").match(/(\d+)/);
    if (match) return parseInt(match[1], 10);
    return null;
  };

  const getPriorityBorder = (priority?: unknown) => {
    const p = String(priority || "").toLowerCase();
    if (p === "urgent") return "border-l-purple-500";
    if (["high", "critical", "vulnerable"].includes(p)) return "border-l-destructive";
    if (["medium", "moderate", "weak"].includes(p)) return "border-l-amber-500";
    if (["low", "pqc", "ready"].includes(p)) return "border-l-emerald-500";
    return "border-l-primary/60";
  };

  const getPriorityHighlight = (priority?: unknown) => {
    const p = String(priority || "").toLowerCase();
    if (p === "urgent") return "bg-purple-500/15 border-purple-500 ring-1 ring-purple-500/40 shadow-sm";
    if (["high", "critical", "vulnerable"].includes(p)) return "bg-destructive/15 border-destructive ring-1 ring-destructive/40 shadow-sm";
    if (["medium", "moderate", "weak"].includes(p)) return "bg-amber-500/15 border-amber-500 ring-1 ring-amber-500/40 shadow-sm";
    if (["low", "pqc", "ready"].includes(p)) return "bg-emerald-500/15 border-emerald-500 ring-1 ring-emerald-500/40 shadow-sm";
    return "bg-primary/15 border-primary ring-1 ring-primary/40 shadow-sm";
  };

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between">
        <div>
          <div className="flex items-center gap-2">
            <SectionLabel>Plan #{plan.id}</SectionLabel>
            <StatusBadge status={plan.status} />
          </div>
          <p className="mt-2 max-w-2xl truncate text-sm text-muted-foreground">{plan.target || "No target reported"}</p>
          <p className="mt-1 text-xs text-muted-foreground">Run #{plan.run_id} · Created {formatDate(plan.created_at)}</p>
        </div>
        {!isTerminalStatus(plan.status) ? (
          <Button variant="outline" size="sm" onClick={onCancel} disabled={cancelling}>
            {cancelling ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" /> : <XCircle className="h-3.5 w-3.5" aria-hidden="true" />}
            Cancel
          </Button>
        ) : null}
      </CardHeader>
      <div className="border-b px-5 pt-4">
        <Progress value={plan.progress} />
        <div className="flex justify-between py-2 text-[11px] text-muted-foreground">
          <span>{isTerminalStatus(plan.status) ? "Terminal state" : "Refreshing plan state"}</span>
          <span className="tnum">{plan.progress}%</span>
        </div>
      </div>
      <CardContent className="space-y-6 p-5">
        {plan.error ? (
          <div className="flex gap-2 border border-destructive/30 bg-destructive/5 p-3 text-xs leading-5 text-destructive">
            <XCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
            {plan.error}
          </div>
        ) : null}
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
          <PlanMetric label="Assets" value={plan.summary?.assets} icon={Shield} />
          <PlanMetric label="Urgent" value={plan.summary?.urgent} icon={AlertTriangle} tone="purple" />
          <PlanMetric label="Quantum-vulnerable" value={plan.summary?.quantum_vulnerable} icon={Route} tone="warning" />
          <PlanMetric label="HNDL exposed" value={plan.summary?.hndl_exposed} icon={AlertTriangle} tone="orange" />
          <PlanMetric label="Blast severity" display={titleCase(plan.summary?.blast_severity || blast.severity)} tone={blast.severity === "CRITICAL" || blast.severity === "HIGH" ? "danger" : blast.severity ? "warning" : "default"} icon={Map} />
        </div>
        <div className="grid gap-4 lg:grid-cols-2">
          <div className="border bg-muted/20 p-4">
            <SectionLabel>Executive summary</SectionLabel>
            <p className="mt-3 text-sm leading-6">{text(document.executive_summary || document.quantum_risk_narrative || "No narrative returned.")}</p>
          </div>
          <div className="border bg-muted/20 p-4">
            <SectionLabel>Blast radius and effort</SectionLabel>
            <div className="mt-3 space-y-2 text-xs">
              <div className="flex justify-between gap-4">
                <span className="text-muted-foreground">Severity</span>
                <span>{titleCase(blast.severity || plan.summary?.blast_severity)}</span>
              </div>
              <div className="flex justify-between gap-4">
                <span className="text-muted-foreground">Effort estimate</span>
                <span>{plan.summary?.effort_estimate_quarters ? `${plan.summary.effort_estimate_quarters} quarters` : "—"}</span>
              </div>
              <div className="flex justify-between gap-4">
                <span className="text-muted-foreground">Services affected</span>
                <span className="tnum">{formatNumber(typeof blast.affected_services === "number" ? blast.affected_services : 0)}</span>
              </div>
              <div className="flex justify-between gap-4">
                <span className="text-muted-foreground">Public surface</span>
                <span>{blast.public_surface ? "Public" : "Not public"}</span>
              </div>
              <div className="flex justify-between gap-4">
                <span className="text-muted-foreground">Weakest primitive</span>
                <span>{titleCase(blast.poorest_link)}</span>
              </div>
            </div>
          </div>
        </div>
        <div>
          <SectionLabel>Asset remediation rows</SectionLabel>
          {rows.length ? (
            <div className="mt-3 overflow-x-auto border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Asset</TableHead>
                    <TableHead>Risk</TableHead>
                    <TableHead>Priority</TableHead>
                    <TableHead>Expected quantum time</TableHead>
                    <TableHead>Replacement</TableHead>
                    <TableHead>Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((value, index) => {
                    const row = record(value);
                    const getExpectedQuantumTime = (r: JsonRecord): string => {
                      if (r.expected_quantum_time) return String(r.expected_quantum_time);
                      if (r.quantum_time) return String(r.quantum_time);
                      if (r.timeline) return String(r.timeline);
                      if (r.time_estimate) return String(r.time_estimate);
                      const wave = typeof r.migration_wave === "number" ? r.migration_wave : typeof r.wave === "number" ? r.wave : null;
                      if (wave === 1) return "0–3 Mos (Wave 1)";
                      if (wave === 2) return "3–12 Mos (Wave 2)";
                      if (wave === 3) return "12–24 Mos (Wave 3)";
                      const priority = String(r.priority || r.migration_priority || r.risk || r.overall_risk || "").toUpperCase();
                      if (priority === "URGENT") return "0–3 Mos (Immediate)";
                      if (priority === "HIGH" || priority === "CRITICAL") return "3–12 Mos (Wave 2)";
                      if (priority === "MEDIUM" || priority === "MODERATE") return "12–24 Mos (Wave 3)";
                      if (priority === "LOW") return "24+ Mos (Long-term)";
                      return "Target 2033";
                    };

                    return (
                      <TableRow key={String(row.asset_id || index)}>
                        <TableCell className="max-w-[220px] truncate font-mono text-xs">{text(row.asset_id || row.name)}</TableCell>
                        <TableCell>{riskBadge(row.risk || row.overall_risk)}</TableCell>
                        <TableCell>{riskBadge(row.priority || row.migration_priority)}</TableCell>
                        <TableCell className="whitespace-nowrap font-mono text-xs text-muted-foreground">
                          <span className="inline-flex items-center gap-1.5 rounded bg-muted/60 px-2 py-0.5 border border-border/50 font-medium">
                            <Clock3 className="h-3 w-3 text-primary shrink-0" aria-hidden="true" />
                            {getExpectedQuantumTime(row)}
                          </span>
                        </TableCell>
                        <TableCell className="max-w-[220px] truncate text-xs text-muted-foreground" title={text(replacementOf(row))}>
                          {text(replacementOf(row))}
                        </TableCell>
                        <TableCell className="max-w-[280px] truncate text-xs text-muted-foreground" title={text(row.recommended_action || row.action)}>
                          {text(row.recommended_action || row.action)}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          ) : (
            <div className="mt-3">
              <EmptyState title="No remediation rows" description="This plan does not list any individual assets." />
            </div>
          )}
        </div>
        <div className="grid gap-6 lg:grid-cols-2">
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <SectionLabel>Migration waves</SectionLabel>
              {hoveredWave !== null ? (
                <span className="text-[11px] font-medium text-primary animate-pulse">
                  Inspecting Wave {hoveredWave}
                </span>
              ) : (
                <span className="text-[11px] text-muted-foreground">Hover to trace pathway</span>
              )}
            </div>

            {waves.length ? (
              <div className="relative pl-6 space-y-3 before:absolute before:left-2.5 before:top-3 before:bottom-3 before:w-0.5 before:bg-gradient-to-b before:from-purple-500 before:via-primary before:to-emerald-500/70">
                {waves.map((value, index) => {
                  const wave = record(value);
                  const waveNum = parseWaveNum(wave, index);
                  const isHovered = hoveredWave === waveNum;
                  const waveRecsCount = recommendations.filter((r) => parseRecWaveNum(record(r)) === waveNum).length;

                  const nodeColor =
                    waveNum === 1
                      ? "bg-purple-500 text-white ring-purple-500/30"
                      : waveNum === 2
                      ? "bg-primary text-primary-foreground ring-primary/30"
                      : "bg-emerald-500 text-white ring-emerald-500/30";

                  return (
                    <div key={index} className="relative group">
                      {/* Luminous Node Bubble on Timeline Spine */}
                      <span
                        className={cn(
                          "absolute -left-6 top-3.5 h-5 w-5 rounded-full flex items-center justify-center font-mono text-[10px] font-bold ring-4 transition-all duration-300 z-10",
                          nodeColor,
                          isHovered ? "scale-125 ring-8 ring-primary/40 shadow-lg" : "scale-100 ring-2"
                        )}
                      >
                        {waveNum}
                      </span>

                      <div
                        onMouseEnter={() => setHoveredWave(waveNum)}
                        onMouseLeave={() => setHoveredWave(null)}
                        className={cn(
                          "flex flex-col gap-2 border p-3.5 text-sm transition-all duration-200 cursor-pointer rounded-md relative overflow-hidden",
                          isHovered
                            ? "border-primary bg-primary/10 shadow-md ring-1 ring-primary/40 -translate-y-0.5"
                            : "border-border/70 bg-card hover:border-border hover:bg-muted/30"
                        )}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex items-center gap-2 min-w-0">
                            <span className="font-semibold text-xs text-foreground tracking-tight">
                              Wave {waveNum}
                            </span>
                            <span className="truncate text-xs text-muted-foreground font-medium" title={text(wave.name || wave.description)}>
                              {text(wave.name || wave.description)}
                            </span>
                          </div>
                          {wave.timeline ? (
                            <span className="text-[11px] font-mono font-medium text-foreground px-2 py-0.5 rounded bg-muted/80 border border-border/50 shrink-0">
                              {String(wave.timeline)}
                            </span>
                          ) : null}
                        </div>

                        <div className="flex items-center justify-between text-[11px] text-muted-foreground pt-1 border-t border-border/30">
                          <span className="flex items-center gap-1">
                            <Route className="h-3 w-3 text-primary" aria-hidden="true" />
                            {waveRecsCount} Linked Recommendation{waveRecsCount === 1 ? "" : "s"}
                          </span>
                          <span className={cn("inline-flex items-center gap-1 font-medium transition-colors", isHovered ? "text-primary" : "text-muted-foreground")}>
                            Trace Wave <ArrowRight className={cn("h-3 w-3 transition-transform", isHovered ? "translate-x-1" : "")} aria-hidden="true" />
                          </span>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <p className="mt-3 text-xs text-muted-foreground">No waves returned.</p>
            )}

            {/* Visual Connected Milestone Execution Topology Card */}
            <div className="border rounded-md bg-muted/10 p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <GitBranch className="h-4 w-4 text-primary" aria-hidden="true" />
                  <span className="text-xs font-semibold uppercase tracking-wider text-foreground">Execution Flow Architecture</span>
                </div>
                <span className="text-[10px] font-mono font-medium text-primary px-2 py-0.5 rounded-full bg-primary/10 border border-primary/20">
                  Target 2033 Horizon
                </span>
              </div>

              <div className="space-y-2 text-xs">
                <div
                  onMouseEnter={() => setHoveredWave(1)}
                  onMouseLeave={() => setHoveredWave(null)}
                  className={cn(
                    "flex items-start gap-3 p-2.5 rounded border transition-all duration-200 cursor-pointer",
                    hoveredWave === 1
                      ? "bg-purple-500/15 border-purple-500/60 ring-1 ring-purple-500/30 -translate-x-0.5"
                      : "bg-background/60 border-border/40 hover:bg-muted/40"
                  )}
                >
                  <span className="h-2 w-2 rounded-full bg-purple-500 mt-1.5 shrink-0 shadow-sm" />
                  <div className="min-w-0 flex-1">
                    <p className="font-semibold text-foreground text-[11px]">Phase 1: Urgent Triage &amp; HNDL Isolation (0–3m)</p>
                    <p className="text-[11px] text-muted-foreground leading-relaxed mt-0.5">
                      Eliminate classically weak primitives (MD5, DES, 3DES, RC4) and stage immediate hybrid handshakes for long-shelf-life data paths.
                    </p>
                  </div>
                </div>

                <div
                  onMouseEnter={() => setHoveredWave(2)}
                  onMouseLeave={() => setHoveredWave(null)}
                  className={cn(
                    "flex items-start gap-3 p-2.5 rounded border transition-all duration-200 cursor-pointer",
                    hoveredWave === 2
                      ? "bg-primary/15 border-primary/60 ring-1 ring-primary/30 -translate-x-0.5"
                      : "bg-background/60 border-border/40 hover:bg-muted/40"
                  )}
                >
                  <span className="h-2 w-2 rounded-full bg-primary mt-1.5 shrink-0 shadow-sm" />
                  <div className="min-w-0 flex-1">
                    <p className="font-semibold text-foreground text-[11px]">Phase 2: Post-Quantum Standard Transition (3–12m)</p>
                    <p className="text-[11px] text-muted-foreground leading-relaxed mt-0.5">
                      Upgrade vulnerable public-key architectures (RSA, ECC) to NIST FIPS 203 (ML-KEM) key exchange and FIPS 204 (ML-DSA) signatures.
                    </p>
                  </div>
                </div>

                <div
                  onMouseEnter={() => setHoveredWave(3)}
                  onMouseLeave={() => setHoveredWave(null)}
                  className={cn(
                    "flex items-start gap-3 p-2.5 rounded border transition-all duration-200 cursor-pointer",
                    hoveredWave === 3
                      ? "bg-emerald-500/15 border-emerald-500/60 ring-1 ring-emerald-500/30 -translate-x-0.5"
                      : "bg-background/60 border-border/40 hover:bg-muted/40"
                  )}
                >
                  <span className="h-2 w-2 rounded-full bg-emerald-500 mt-1.5 shrink-0 shadow-sm" />
                  <div className="min-w-0 flex-1">
                    <p className="font-semibold text-foreground text-[11px]">Phase 3: Symmetric Hardening &amp; CI/CD Guardrails (12–24m)</p>
                    <p className="text-[11px] text-muted-foreground leading-relaxed mt-0.5">
                      Consolidate to AES-256-GCM / SHA-384 and embed automated ECDAT CBOM cryptographic linting into build pipelines to prevent regressions.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between">
              <SectionLabel>Recommendations</SectionLabel>
              <span className="text-[11px] text-muted-foreground">
                {hoveredWave !== null ? `Filtered by Wave ${hoveredWave}` : "Hover wave to inspect"}
              </span>
            </div>
            {recommendations.length ? (
              <ul className="mt-3 space-y-3">
                {recommendations.map((value, index) => {
                  const rec = record(value);
                  const actions = array(rec.actions);
                  const recWave = parseRecWaveNum(rec);
                  const isWaveMatch = hoveredWave !== null && recWave === hoveredWave;
                  const isDimmed = hoveredWave !== null && recWave !== hoveredWave;

                  return (
                    <li
                      key={index}
                      onMouseEnter={() => recWave !== null && setHoveredWave(recWave)}
                      onMouseLeave={() => setHoveredWave(null)}
                      className={cn(
                        "border-l-4 pl-3.5 py-2.5 pr-3 rounded-r-md transition-all duration-200 cursor-pointer border border-transparent",
                        getPriorityBorder(rec.priority),
                        isWaveMatch
                          ? cn(getPriorityHighlight(rec.priority), "translate-x-1")
                          : isDimmed
                          ? "opacity-35 bg-transparent"
                          : "bg-muted/15 hover:bg-muted/35 hover:border-border/60"
                      )}
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex flex-wrap items-center gap-2">
                          <p className="text-sm font-medium text-foreground">{text(rec.title)}</p>
                          {rec.priority ? riskBadge(rec.priority) : null}
                        </div>
                        {recWave !== null ? (
                          <span
                            className={cn(
                              "text-[10px] font-mono px-2 py-0.5 rounded font-semibold transition-colors",
                              isWaveMatch
                                ? "bg-primary text-primary-foreground shadow-xs"
                                : "bg-muted/80 text-muted-foreground border border-border/50"
                            )}
                          >
                            Wave {recWave}
                          </span>
                        ) : null}
                      </div>
                      {rec.description ? (
                        <p className="mt-1.5 text-xs leading-5 text-muted-foreground">{text(rec.description)}</p>
                      ) : null}
                      {actions.length ? (
                        <ul className="mt-2 list-inside list-disc space-y-0.5 text-xs text-muted-foreground">
                          {actions.map((action, actionIndex) => (
                            <li key={actionIndex}>{text(action)}</li>
                          ))}
                        </ul>
                      ) : null}
                    </li>
                  );
                })}
              </ul>
            ) : (
              <p className="mt-3 text-xs text-muted-foreground">No recommendations returned.</p>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
