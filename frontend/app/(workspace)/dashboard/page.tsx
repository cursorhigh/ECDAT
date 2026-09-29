"use client";

import { useState } from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { Activity, ArrowRight, Boxes, Check, CircleHelp, Clock, FileBarChart, Radar, ScanLine, ShieldAlert } from "lucide-react";
import { Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Button, buttonVariants } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { RefreshButton } from "@/components/ui/refresh-button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { MetricCard } from "@/components/data/metric-card";
import { ErrorState, EmptyState, LoadingState } from "@/components/feedback/data-state";
import { PageHeader, SectionLabel } from "@/components/data/page-header";
import { PipelineProgress, stageRoute } from "@/components/data/pipeline-progress";
import { riskBadge } from "@/components/data/status-badge";
import { api } from "@/lib/api/client";
import type { ReportingOverview } from "@/lib/api/types";
import { useSession } from "@/lib/session-context";
import { formatNumber, refetchAllOrThrow, titleCase, truncate } from "@/lib/utils";

const riskColors: Record<string, string> = {
  vulnerable: "hsl(var(--destructive))",
  weak: "hsl(var(--warning))",
  moderate: "hsl(35 85% 58%)",
  pqc: "hsl(var(--success))",
  unknown: "hsl(var(--muted-foreground))"
};

/**
 * Categorical palette for the inventory pie, ordered so the largest slice gets
 * the most distinguishable colour. Wraps past eight families: the legend keeps
 * the label and count, so a ninth slice degrades to a repeated colour rather
 * than an unreadable chart.
 */
const FAMILY_COLORS = [
  "hsl(210 70% 52%)",
  "hsl(280 55% 60%)",
  "hsl(150 55% 42%)",
  "hsl(28 82% 55%)",
  "hsl(340 62% 58%)",
  "hsl(190 60% 45%)",
  "hsl(48 75% 48%)",
  "hsl(258 50% 58%)"
];

/**
 * How much of the above to believe.
 *
 * Every headline number is only as good as the scan behind it, so the coverage
 * and the unassessable remainder are shown rather than buried: a dashboard that
 * quotes 11 assets without saying it read 4 sources, or that quietly folds
 * "could not assess" into zero, is overstating its own case.
 */
function EvidenceNote({ kpis }: { kpis: ReportingOverview["kpis"] | undefined }) {
  if (!kpis) return null;
  const coverage = kpis.coverage_pct || 0;
  const notAssessable = kpis.not_assessable || 0;
  const assessed = kpis.assessed || 0;

  return (
    <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border bg-card px-4 py-2.5 text-[11px] text-muted-foreground">
      <span className="flex items-center gap-1.5">
        <ScanLine className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
        <span className="text-foreground">Evidence</span>
        <span>
          {formatNumber(kpis.sources_scanned || 0)} source{kpis.sources_scanned === 1 ? "" : "s"} scanned
        </span>
      </span>
      <span aria-hidden="true" className="text-muted-foreground/30">
        |
      </span>
      <span>
        {coverage}% of reported items inspected
        {kpis.items_total ? ` (${formatNumber(kpis.items_scanned)}/${formatNumber(kpis.items_total)})` : ""}
      </span>
      {assessed ? (
        <>
          <span aria-hidden="true" className="text-muted-foreground/30">
            |
          </span>
          <span className={notAssessable > 0 ? "text-amber-600 dark:text-amber-400" : undefined}>
            {formatNumber(notAssessable)} of {formatNumber(assessed)} findings not assessable
            {notAssessable > 0 ? " — supply operational context in risk analysis" : ""}
          </span>
        </>
      ) : (
        <>
          <span aria-hidden="true" className="text-muted-foreground/30">
            |
          </span>
          <span>Risk analysis has not run, so nothing here is scored yet</span>
        </>
      )}
    </div>
  );
}

export default function DashboardPage() {
  const { ready, scopeKey, info , hasSession } = useSession();
  const [processOpen, setProcessOpen] = useState(false);
  const overview = useQuery({ queryKey: ["dashboard", "overview", scopeKey], queryFn: api.reportingOverview, enabled: ready && hasSession });
  const stats = useQuery({ queryKey: ["dashboard", "stats", scopeKey], queryFn: api.stats, enabled: ready && hasSession });

  const retry = async () => {
    await refetchAllOrThrow([overview, stats]);
  };

  if (overview.isLoading) return <LoadingState label="Loading estate posture" />;
  if (overview.isError) return <ErrorState message={overview.error instanceof Error ? overview.error.message : undefined} onRetry={retry} />;

  const data = overview.data;
  const kpis = data?.kpis;
  const riskData = data?.risk_split || [];
  const priorities = data?.vuln_priorities?.slice(0, 6) || [];
  const workflow = data?.workflow || [];
  // The pie plots a composition, so it needs slices that genuinely sum to the
  // whole. Families do (they reconcile to asset_total); the pipeline counts
  // below do not, so they stay as plain numbers.
  const familyRows = (stats.data?.asset_by_family || [])
    .filter((row) => (row.family || "").trim() !== "")
    .map((row, index) => {
      const value = row.count || 0;
      return {
        name: row.family || "unknown",
        value,
        color: FAMILY_COLORS[index % FAMILY_COLORS.length],
        pct: stats.data?.asset_total ? Math.round((value / stats.data.asset_total) * 100) : 0
      };
    })
    .sort((a, b) => b.value - a.value);

  return (
    <div className="space-y-6">
      <PageHeader compact eyebrow={info?.session_name || "No scan selected"} title="Security posture" actions={<><Button type="button" variant="outline" size="icon" className="rounded-full" onClick={() => setProcessOpen(true)} aria-label="How the ECDAT workflow works" title="How the ECDAT workflow works"><CircleHelp className="h-4 w-4" aria-hidden="true" /></Button><RefreshButton onRefresh={retry} /><Link href="/scans" className={buttonVariants({ variant: "outline", size: "sm" })}><Radar className="h-3.5 w-3.5" aria-hidden="true" />New scan</Link><Link href="/reports" className={buttonVariants({ size: "sm" })}><FileBarChart className="h-3.5 w-3.5" aria-hidden="true" />Reports</Link></>} />

      <PipelineProgress
        stages={workflow}
        running={(data?.scan_running || 0) + (data?.analysis_running || 0) > 0}
      />

      {/*
        Headline numbers, chosen against what an executive is asked to fund and
        to report on: how much cryptography exists, how much of it a CRQC
        breaks, how much work migration implies, and how much long-lived data
        is already exposed.

        The first two are counted in deduplicated assets; the last two in
        findings, because risk is assessed per finding. The counts differ by an
        order of magnitude, so each card states its own unit rather than
        letting the two kinds sit side by side as if they were comparable.
      */}
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          label="Cryptographic assets"
          value={kpis?.assets}
          detail={`${formatNumber(kpis?.sources_scanned || 0)} sources · ${formatNumber(kpis?.findings || 0)} findings`}
          icon={Boxes}
          href="/assets"
        />
        <MetricCard
          label="Quantum-vulnerable"
          value={kpis?.quantum_vuln}
          detail={`${formatNumber(kpis?.quantum_vuln_pct || 0)}% of inventory`}
          icon={ShieldAlert}
          tone="danger"
          href="/analysis"
        />
        <MetricCard
          label="Assets needing migration"
          value={kpis?.needs_migration_assets}
          detail={`${formatNumber(kpis?.needs_migration || 0)} of ${formatNumber(kpis?.assessed || 0)} findings flagged · across ${formatNumber(kpis?.needs_migration_assets || 0)} distinct assets`}
          icon={ArrowRight}
          tone="danger"
          href="/analysis"
        />
        <MetricCard
          label="HNDL exposure"
          value={kpis?.hndl_exposed_assets}
          detail={
            kpis?.assessed
              ? `${formatNumber(kpis?.hndl_exposed || 0)} of ${formatNumber(kpis?.assessed)} findings carry long-lived data`
              : "Run risk analysis to measure this"
          }
          icon={Clock}
          tone="danger"
          href="/analysis"
        />
      </div>

      <EvidenceNote kpis={kpis} />

      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader className="flex-row items-start justify-between"><div><CardTitle>Risk distribution</CardTitle><p className="mt-1 text-xs text-muted-foreground">How discovered assets are classified by the current risk model.</p></div><Link href="/assets" className="text-xs text-primary hover:underline">View assets</Link></CardHeader>
          <CardContent>
            {riskData.length ? <div className="h-[240px] w-full text-foreground"><ResponsiveContainer width="100%" height="100%"><BarChart data={riskData} layout="vertical" margin={{ top: 4, right: 12, left: 4, bottom: 0 }}><CartesianGrid horizontal={false} stroke="hsl(var(--border))" /><XAxis type="number" allowDecimals={false} tick={{ fill: "currentColor", fontSize: 11 }} /><YAxis type="category" dataKey="label" width={92} tick={{ fill: "currentColor", fontSize: 11 }} axisLine={false} tickLine={false} /><Tooltip cursor={{ fill: "hsl(var(--muted))" }} contentStyle={{ background: "hsl(var(--popover))", border: "1px solid hsl(var(--border))", borderRadius: 0, color: "hsl(var(--popover-foreground))", fontSize: 12, padding: "10px 12px" }} labelStyle={{ color: "hsl(var(--popover-foreground))", fontSize: 12, fontWeight: 600 }} itemStyle={{ color: "hsl(var(--popover-foreground))", fontSize: 12 }} /><Bar dataKey="count" radius={0} barSize={18}>{riskData.map((row) => <Cell key={row.key} fill={riskColors[row.key] || riskColors.unknown} />)}</Bar></BarChart></ResponsiveContainer></div> : <EmptyState title="No risk distribution yet" description="No risk categories are available for this scope." />}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex-row flex-wrap items-center justify-between gap-3">
            <div>
              <CardTitle>Inventory composition</CardTitle>
              <p className="mt-1 text-xs text-muted-foreground">
                How the {formatNumber(stats.data?.asset_total)} recorded assets break down by family.
              </p>
            </div>
            <Activity className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          </CardHeader>
          <CardContent className="space-y-4">
            {stats.isError ? (
              <p className="text-xs text-destructive">Stats are unavailable for this scope.</p>
            ) : familyRows.length ? (
              <>
                <div className="flex items-center gap-4">
                  <div className="h-[132px] w-[132px] shrink-0">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={familyRows}
                          dataKey="value"
                          nameKey="name"
                          innerRadius={38}
                          outerRadius={62}
                          paddingAngle={1.5}
                          stroke="none"
                          isAnimationActive={false}
                        >
                          {familyRows.map((row) => (
                            <Cell key={row.name} fill={row.color} />
                          ))}
                        </Pie>
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                  {/*
                    A legend rather than a recharts <Tooltip>: the family names
                    are long, the counts are small, and a hover-only readout
                    would hide the numbers on touch and in print.
                  */}
                  <ul className="min-w-0 flex-1 space-y-1.5">
                    {familyRows.map((row) => (
                      <li key={row.name} className="flex items-center gap-2 text-[11px]">
                        <span
                          aria-hidden="true"
                          className="h-2 w-2 shrink-0"
                          style={{ backgroundColor: row.color }}
                        />
                        <span className="min-w-0 flex-1 truncate text-muted-foreground" title={row.name}>
                          {titleCase(row.name)}
                        </span>
                        <span className="tnum shrink-0 font-medium text-foreground">
                          {formatNumber(row.value)}
                        </span>
                        <span className="tnum w-9 shrink-0 text-right text-muted-foreground">
                          {row.pct}%
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/*
                  Pipeline telemetry, kept as plain numbers. These are different
                  measurements at different stages -- summing them into the pie
                  above would double-count the same findings twice.
                */}
                <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t pt-3 text-[11px] text-muted-foreground">
                  {[
                    ["Findings", stats.data?.raw_total],
                    ["Normalized", stats.data?.normalized_total],
                    ["Relations", stats.data?.relation_total],
                    ["Dependencies", stats.data?.dependency_total],
                    ["Audit events", stats.data?.audit_total]
                  ].map(([label, value]) => (
                    <span key={String(label)}>
                      {label} <span className="tnum font-medium text-foreground">{formatNumber(value as number | undefined)}</span>
                    </span>
                  ))}
                </div>
              </>
            ) : (
              <EmptyState
                title="Nothing recorded yet"
                description="Run a discovery scan to build the inventory."
                action={
                  <Link href="/scans" className={buttonVariants({ size: "sm" })}>
                    Start discovery
                    <ArrowRight className="ml-1.5 h-3.5 w-3.5" aria-hidden="true" />
                  </Link>
                }
              />
            )}
          </CardContent>
        </Card>
      </div>

      <Card className="min-w-0">
        <CardHeader className="flex-row items-center justify-between gap-3">
          <div>
            <CardTitle>Migration priorities</CardTitle>
            <p className="mt-1 text-xs text-muted-foreground">
              Assets ranked by the current vulnerability and key-size signals.
            </p>
          </div>
          <Link href="/analysis" className="shrink-0 text-xs text-primary hover:underline">
            Risk analysis
            <ArrowRight className="ml-1 inline h-3 w-3" aria-hidden="true" />
          </Link>
        </CardHeader>
        <CardContent className="p-0">
          {priorities.length ? (
            <Table className="table-fixed">
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[30%] whitespace-normal px-3">Asset</TableHead>
                  <TableHead className="w-[16%] whitespace-normal px-3">Algorithm</TableHead>
                  <TableHead className="w-[12%] whitespace-normal px-3">Risk</TableHead>
                  <TableHead className="w-[42%] whitespace-normal px-3">Replacement</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {priorities.map((row) => (
                  <TableRow key={`${row.asset.id}-${row.score}`}>
                    <TableCell className="min-w-0 px-3">
                      <p className="truncate font-medium" title={row.asset.name}>{row.asset.name}</p>
                      <p className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground" title={row.asset.location || "No location reported"}>
                        {truncate(row.asset.location || "No location reported", 46)}
                      </p>
                    </TableCell>
                    <TableCell className="min-w-0 px-3">
                      <span className="block truncate font-mono text-xs" title={row.asset.algorithm || row.asset.family || "Unknown"}>
                        {row.asset.algorithm || row.asset.family || "Unknown"}
                      </span>
                      <span className="mt-0.5 block truncate text-[11px] text-muted-foreground">
                        {row.asset.key_size ? `${row.asset.key_size} bits` : ""}
                      </span>
                    </TableCell>
                    <TableCell className="px-3">{riskBadge(row.risk_label)}</TableCell>
                    <TableCell className="min-w-0 px-3">
                      <p className="truncate text-xs text-muted-foreground" title={row.replacement}>{row.replacement}</p>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="p-5">
              <EmptyState
                title="No migration priorities"
                description="No vulnerable or weak assets are currently identified in this scope."
              />
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog
        variant="dark"
        className="max-w-2xl ring-1 ring-white/10"
        open={processOpen}
        onOpenChange={setProcessOpen}
        title="How ECDAT works"
        description="Each stage runs over evidence discovery has actually recorded, and each links to the page where you act on it."
      >
        {workflow.length ? (
          <ol className="divide-y divide-white/10 border-y border-white/10">
            {workflow.map((stage, index) => (
              <li key={stage.key} className="flex items-start gap-3 py-2.5 first:pt-2 last:pb-2">
                <span
                  className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center border text-[10px] font-semibold ${
                    stage.done ? "border-white/30 bg-white/10 text-white" : "border-white/15 text-white/50"
                  }`}
                >
                  {stage.done ? <Check className="h-3 w-3" aria-hidden="true" /> : String(index + 1).padStart(2, "0")}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex items-baseline justify-between gap-3">
                    <p className="truncate text-xs font-medium text-white">{stage.name}</p>
                    <span className="tnum shrink-0 text-[11px] text-white/50">{formatNumber(stage.count)}</span>
                  </div>
                  <p className="mt-0.5 text-[11px] leading-4 text-white/50">{stage.detail}</p>
                  {stage.sub?.length ? (
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {stage.sub.map((item) => (
                        <span key={item.label} className="border border-white/15 bg-white/5 px-1.5 py-0.5 text-[10px] text-white/60">
                          {item.label} {formatNumber(item.count)}
                        </span>
                      ))}
                    </div>
                  ) : null}
                </div>
                <Link
                  href={stageRoute(stage.api)}
                  onClick={() => setProcessOpen(false)}
                  className="mt-0.5 shrink-0 text-[11px] text-white/80 underline underline-offset-4 hover:text-white"
                >
                  Open
                  <span className="sr-only"> {stage.name}</span>
                </Link>
              </li>
            ))}
          </ol>
        ) : (
          <EmptyState title="No workflow data" description="Run a discovery scan to see the stages." />
        )}
        <p className="mt-3 text-[11px] leading-4 text-white/40">
          Counts are read from stored records, never inferred. Missing coverage is reported rather than
          filled in, and the audit trail is append-only, so a stage cannot be quietly edited away.
        </p>
      </Dialog>
    </div>
  );
}
