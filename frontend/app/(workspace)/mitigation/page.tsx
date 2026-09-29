"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertCircle, AlertTriangle, Clock3, Info, Loader2, Map, Route, Shield, ShieldAlert, ShieldCheck, XCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { RefreshButton } from "@/components/ui/refresh-button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { NavTooltip } from "@/components/ui/nav-tooltip";
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
            /*
             * Bounded and scrollable, with a sticky header. This list grows by one
             * row per plan ever generated for the scan, and nothing capped it, so
             * the card pushed the whole plan detail -- waves, recommendations and
             * remediation rows -- off the page. The heading is deliberately left
             * outside the scroll so the scope line stays readable while you scroll
             * through plans.
             */
            <div className="max-h-[28rem] overflow-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="sticky top-0 z-10 bg-card" title="The plan, by number and name.">Plan</TableHead>
                    <TableHead className="sticky top-0 z-10 bg-card" title="What this plan covers.">Target</TableHead>
                    <TableHead className="sticky top-0 z-10 bg-card" title="Where the plan is in its own lifecycle.">Status</TableHead>
                    <TableHead className="sticky top-0 z-10 bg-card" title="How far through the plan's work it is.">Progress</TableHead>
                    <TableHead className="sticky top-0 z-10 bg-card" title="How many assets in this plan are marked urgent.">Urgent</TableHead>
                    <TableHead className="sticky top-0 z-10 bg-card" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {plans.data.map((plan) => (
                    <PlanRow key={plan.id} plan={plan} selected={plan.id === activePlanId} onSelect={() => setSelectedId(plan.id)} />
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <div className="p-5"><EmptyState title="No mitigation plans" description="Generate a plan from a completed analysis run." /></div>
          )}
        </CardContent>
      </Card>

      {activePlanId ? <PlanDetail plan={selectedPlan} loading={detail.isLoading} error={detail.error instanceof Error ? detail.error.message : undefined} onCancel={() => cancel.mutate(activePlanId)} cancelling={cancel.isPending} /> : <Card><CardContent className="p-5"><EmptyState title="Select a plan" description="Choose a mitigation plan to inspect its plan document." /></CardContent></Card>}
    </div>
  );
}

/*
 * Wave number and recommendation-to-wave matching.
 *
 * Lifted to module scope: both are pure functions of their argument, and the wave
 * chevrons are their own component now. Reading the number out of the name is
 * deliberate -- plans have been seen with the wave given only in prose, and an
 * explicit field is preferred whenever one is present.
 */
function parseWaveNum(waveObj: JsonRecord, index: number): number {
  if (typeof waveObj.wave === "number") return waveObj.wave;
  if (typeof waveObj.wave_number === "number") return waveObj.wave_number;
  const match = String(waveObj.name || "").match(/Wave\s*(\d+)/i);
  if (match) return parseInt(match[1], 10);
  return index + 1;
}

function parseRecWaveNum(recObj: JsonRecord): number | null {
  if (typeof recObj.wave === "number") return recObj.wave;
  if (typeof recObj.wave_number === "number") return recObj.wave_number;
  const match = String(recObj.wave || "").match(/(\d+)/);
  if (match) return parseInt(match[1], 10);
  return null;
}

/*
 * What each wave is for, in one line.
 *
 * This was the only thing the hardcoded "Execution Flow Architecture" box carried
 * that the plan data did not, so it stays -- but as a tooltip instead of a second
 * column of prose, and clearly marked as guidance rather than read off the plan.
 * A plan with four waves therefore does not silently inherit a fourth phase that
 * nobody wrote about.
 */
const PHASE_INTENT: Record<number, string> = {
  1: "Remove classically weak primitives (MD5, DES, 3DES, RC4) and stage hybrid handshakes for long-shelf-life data.",
  2: "Move vulnerable public-key use (RSA, ECC) to FIPS 203 ML-KEM key exchange and FIPS 204 ML-DSA signatures.",
  3: "Consolidate to AES-256-GCM / SHA-384 and put automated CBOM linting into the build pipeline.",
};

/*
 * Notched top and bottom, flat sides: the horizontal chevron turned on its side.
 *
 * The horizontal version read left-to-right, which fought a column that is only a
 * fifth of the page wide -- three wide arrows in a narrow strip looked like three
 * unrelated buttons. Pointed down they read as a path falling through time, which
 * is what a migration wave is, and they stack without needing the width that made
 * them look wrong.
 *
 * `(50% 0)` and `(50% 100%)` are the points; the `16px` / `calc(100% - 20px)` insets
 * are the notch, so consecutive waves interlock instead of leaving a gap.
 */
const WAVE_CHEVRON =
  "polygon(100% 16px, 100% calc(100% - 20px), 50% 100%, 0 calc(100% - 20px), 0 16px, 50% 0)";

const WAVE_SURFACE: Record<number, string> = {
  1: "border-purple-500/40 bg-purple-500/10 text-purple-700 dark:text-purple-300",
  2: "border-primary/40 bg-primary/10 text-primary",
  3: "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
};

function WaveStrip({
  waves,
  recommendations,
  hoveredWave,
  onHover,
}: {
  waves: unknown[];
  recommendations: unknown[];
  hoveredWave: number | null;
  onHover: (wave: number | null) => void;
}) {
  if (!waves.length) {
    return <p className="text-xs text-muted-foreground">This plan has no migration waves.</p>;
  }

  return (
    <div className="flex h-full flex-col">
      <div className="mb-2 flex shrink-0 items-center justify-between">
        <SectionLabel>Migration waves</SectionLabel>
        <span className="tnum text-[11px] text-muted-foreground">
          {waves.length} wave{waves.length === 1 ? "" : "s"}
        </span>
      </div>

      {/*
       * Stacked, with each wave pulled up over the one below it. The overlap is
       * what turns three separate shapes into one continuous ribbon: the downward
       * point of a wave seats into the upward notch of the next. The first one is
       * pushed down by half a notch so the column starts flush with the label
       * above rather than hanging a point into it.
       */}
      <div className="flex flex-1 flex-col">
        {waves.map((value, index) => {
          const wave = record(value);
          const waveNum = parseWaveNum(wave, index);
          const isHovered = hoveredWave === waveNum;
          const recCount = recommendations.filter((r) => parseRecWaveNum(record(r)) === waveNum).length;
          const timeline = text(wave.timeline);
          const name = text(wave.name || wave.description);
          const intent = PHASE_INTENT[waveNum];

          return (
            <button
              key={index}
              type="button"
              onMouseEnter={() => onHover(waveNum)}
              onMouseLeave={() => onHover(null)}
              onFocus={() => onHover(waveNum)}
              onBlur={() => onHover(null)}
              aria-label={`Wave ${waveNum}${timeline ? `, ${timeline}` : ""}, ${recCount} linked recommendations`}
              style={{ clipPath: WAVE_CHEVRON }}
              className={cn(
                "group flex min-h-[4.5rem] w-full flex-1 items-center gap-2.5 border-x px-4 text-left transition-all duration-150",
                WAVE_SURFACE[waveNum] || "border-border bg-muted/40 text-foreground",
                isHovered ? "brightness-110" : "opacity-75 hover:opacity-100",
                // The clip-path swallows the horizontal borders at the points, so
                // the notch would show through as a gap. An inset ring redraws the
                // outline the clip cuts away.
                "ring-1 ring-inset ring-background",
                // Seat each wave into the notch of the one below it. The first is
                // offset by half a notch so the ribbon starts level.
                index === 0 ? "mt-2" : "-mt-2.5"
              )}
            >
              <span className="shrink-0 font-mono text-xl font-semibold leading-none tabular-nums">
                {waveNum}
              </span>
              <span className="min-w-0 flex-1">
                <span className="block text-[10px] font-semibold uppercase tracking-[0.12em] opacity-70">
                  Wave {waveNum}
                </span>
                <span className="tnum mt-0.5 block font-mono text-[11px]">{timeline || "—"}</span>
              </span>
              <span
                className="tnum shrink-0 rounded-full border border-current/40 px-1.5 text-[10px] leading-4"
                title={`${recCount} linked recommendation${recCount === 1 ? "" : "s"}`}
              >
                {recCount}
              </span>
              {name || intent ? (
                <NavTooltip
                  title={name || `Wave ${waveNum}`}
                  description={
                    <>
                      {intent ? <span className="block">{intent}</span> : null}
                      <span className="mt-1 block">
                        {recCount} linked recommendation{recCount === 1 ? "" : "s"}
                      </span>
                    </>
                  }
                  side="bottom"
                >
                  <span className="block">
                    <Info className="h-3.5 w-3.5 opacity-60" aria-hidden="true" />
                  </span>
                </NavTooltip>
              ) : null}
            </button>
          );
        })}
      </div>
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
          {/*
           * Bounded on both axes. This table has one row per asset in the plan and
           * only `overflow-x-auto`, so a plan covering a few hundred assets grew
           * the page until the section heading and the wave strip above it were
           * scrolled out of reach. Capping the height keeps the heading visible
           * and lets the list scroll inside its own panel, with the header sticky
           * so the six columns stay named while you read down.
           */}
          {rows.length ? (
            <div className="mt-3 max-h-[32rem] overflow-auto border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="sticky top-0 z-10 bg-card" title="The asset this remediation row applies to, by id or name.">Asset</TableHead>
                    <TableHead className="sticky top-0 z-10 bg-card" title="The risk this asset currently carries, as assessed by the analysis.">Risk</TableHead>
                    <TableHead className="sticky top-0 z-10 bg-card" title="How urgently it should be remediated, relative to the other assets in the plan.">Priority</TableHead>
                    <TableHead className="sticky top-0 z-10 bg-card" title="When this asset is expected to become harvestable by a quantum attacker. Shown from the plan where recorded, otherwise derived from its migration wave.">Expected quantum time</TableHead>
                    <TableHead className="sticky top-0 z-10 bg-card" title="What this asset should move to.">Replacement</TableHead>
                    <TableHead className="sticky top-0 z-10 bg-card" title="The concrete change to make, as written by the analysis.">Action</TableHead>
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
        {/*
         * 20/80, not 50/50.
         *
         * The waves column is a single narrow strip and the recommendations list
         * beside it is a full table, so an even split gave the chevrons half the
         * page to say three numbers and starved the list of the room it needed.
         * 1fr/4fr is the 20/80 the layout wants. `items-start` stops the shorter
         * column stretching to match the taller one, which was the other half of
         * "equal width, unequal height": equal boxes with one of them mostly air.
         */}
        <div className="grid gap-6 lg:grid-cols-[1fr_4fr]">
          {/*
           * The three waves, as three arrow heads.
           *
           * This replaces two blocks that said the same thing twice: a timeline
           * of wave cards built from the plan data, and an "Execution Flow
           * Architecture" box whose three phases were hardcoded prose describing
           * the same waves. The second was the larger of the two and could not
           * disagree with the data because it was not reading any -- it would
           * happily claim a plan had three phases whatever the plan said. So it is
           * gone, and what it uniquely carried -- the intent of each phase -- is
           * now in the chevron's tooltip, where it was already being skimmed past.
           *
           * Shape carries the sequence: they interlock left to right, and the
           * notch means a wave begins where the previous one ended.
           */}
          <WaveStrip
            waves={waves}
            recommendations={recommendations}
            hoveredWave={hoveredWave}
            onHover={setHoveredWave}
          />

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
