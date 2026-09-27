"use client";

import { useState } from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { Activity, ArrowRight, Boxes, Check, CircleHelp, FileBarChart, Radar, ShieldAlert, Sparkles } from "lucide-react";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Button, buttonVariants } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { RefreshButton } from "@/components/ui/refresh-button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { MetricCard } from "@/components/data/metric-card";
import { ErrorState, EmptyState, LoadingState } from "@/components/feedback/data-state";
import { PageHeader, SectionLabel } from "@/components/data/page-header";
import { StatusBadge, riskBadge } from "@/components/data/status-badge";
import { api } from "@/lib/api/client";
import { useSession } from "@/lib/session-context";
import { formatDate, formatNumber, refetchAllOrThrow, titleCase, truncate } from "@/lib/utils";

const riskColors: Record<string, string> = {
  vulnerable: "hsl(var(--destructive))",
  weak: "hsl(var(--warning))",
  moderate: "hsl(35 85% 58%)",
  pqc: "hsl(var(--success))",
  unknown: "hsl(var(--muted-foreground))"
};

export default function DashboardPage() {
  const { ready, scopeKey, info , hasSession } = useSession();
  const [processOpen, setProcessOpen] = useState(false);
  const overview = useQuery({ queryKey: ["dashboard", "overview", scopeKey], queryFn: api.reportingOverview, enabled: ready && hasSession });
  const stats = useQuery({ queryKey: ["dashboard", "stats", scopeKey], queryFn: api.stats, enabled: ready && hasSession });
  // Keyed under the shared "scans" prefix so the Scans page's invalidations
  // reach this query, but with the ordering included so pages requesting a
  // different order never read each other's cached payload.
  const scans = useQuery({ queryKey: ["scans", scopeKey, "created_at"], queryFn: () => api.scans({ ordering: "created_at", page: 1 }), enabled: ready && hasSession });

  const retry = async () => {
    await refetchAllOrThrow([overview, stats, scans]);
  };

  if (overview.isLoading) return <LoadingState label="Loading estate posture" />;
  if (overview.isError) return <ErrorState message={overview.error instanceof Error ? overview.error.message : undefined} onRetry={retry} />;

  const data = overview.data;
  const kpis = data?.kpis;
  const riskData = data?.risk_split || [];
  const recentScans = scans.data?.results?.slice(0, 5) || [];
  const priorities = data?.vuln_priorities?.slice(0, 6) || [];
  const workflow = data?.workflow || [];

  return (
    <div className="space-y-6">
      <PageHeader compact eyebrow={info?.session_name || "No scan selected"} title="Security posture" description="A live view of discovered cryptographic assets, quantum exposure, and migration readiness in the active scan." actions={<><Button type="button" variant="outline" size="icon" className="rounded-full" onClick={() => setProcessOpen(true)} aria-label="How the ECDAT workflow works" title="How the ECDAT workflow works"><CircleHelp className="h-4 w-4" aria-hidden="true" /></Button><RefreshButton onRefresh={retry} /><Link href="/scans" className={buttonVariants({ variant: "outline", size: "sm" })}><Radar className="h-3.5 w-3.5" aria-hidden="true" />New scan</Link><Link href="/reports" className={buttonVariants({ size: "sm" })}><FileBarChart className="h-3.5 w-3.5" aria-hidden="true" />Reports</Link></>} />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Cryptographic assets" value={kpis?.assets} detail="Discovered in active scope" icon={Boxes} href="/assets" />
        <MetricCard label="Quantum-vulnerable" value={kpis?.quantum_vuln} detail={`${formatNumber(kpis?.quantum_vuln_pct || 0)}% of inventory`} icon={ShieldAlert} tone="danger" href="/analysis" />
        <MetricCard label="PQC-ready" value={kpis?.pqc_ready} detail={`${formatNumber(kpis?.pqc_ready_pct || 0)}% of inventory`} icon={Sparkles} tone="accent" />
        <MetricCard label="Discovery runs" value={kpis?.scans} detail={`${formatNumber(data?.scan_running || 0)} in progress`} icon={Activity} href="/scans" />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader className="flex-row items-start justify-between"><div><CardTitle>Risk distribution</CardTitle><p className="mt-1 text-xs text-muted-foreground">How discovered assets are classified by the current risk model.</p></div><Link href="/assets" className="text-xs text-primary hover:underline">View assets</Link></CardHeader>
          <CardContent>
            {riskData.length ? <div className="h-[240px] w-full text-foreground"><ResponsiveContainer width="100%" height="100%"><BarChart data={riskData} layout="vertical" margin={{ top: 4, right: 12, left: 4, bottom: 0 }}><CartesianGrid horizontal={false} stroke="hsl(var(--border))" /><XAxis type="number" allowDecimals={false} tick={{ fill: "currentColor", fontSize: 11 }} /><YAxis type="category" dataKey="label" width={92} tick={{ fill: "currentColor", fontSize: 11 }} axisLine={false} tickLine={false} /><Tooltip cursor={{ fill: "hsl(var(--muted))" }} contentStyle={{ background: "hsl(var(--popover))", border: "1px solid hsl(var(--border))", borderRadius: 0, color: "hsl(var(--popover-foreground))", fontSize: 12, padding: "10px 12px" }} labelStyle={{ color: "hsl(var(--popover-foreground))", fontSize: 12, fontWeight: 600 }} itemStyle={{ color: "hsl(var(--popover-foreground))", fontSize: 12 }} /><Bar dataKey="count" radius={0} barSize={18}>{riskData.map((row) => <Cell key={row.key} fill={riskColors[row.key] || riskColors.unknown} />)}</Bar></BarChart></ResponsiveContainer></div> : <EmptyState title="No risk distribution yet" description="No risk categories are available for this scope." />}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex-row items-center justify-between"><div><CardTitle>Inventory facts</CardTitle><p className="mt-1 text-xs text-muted-foreground">What discovery has recorded in this scope.</p></div><Activity className="h-4 w-4 text-muted-foreground" aria-hidden="true" /></CardHeader>
          <CardContent className="space-y-3">{stats.isError ? <p className="text-xs text-destructive">Stats are unavailable for this scope.</p> : <>{[["Raw findings", stats.data?.raw_total], ["Normalized findings", stats.data?.normalized_total], ["Asset relations", stats.data?.relation_total], ["Dependencies", stats.data?.dependency_total], ["Dependency links", stats.data?.dependency_edge_total], ["Audit events", stats.data?.audit_total]].map(([label, value]) => <div key={String(label)} className="flex items-center justify-between border-b pb-3 last:border-0 last:pb-0"><span className="text-sm text-muted-foreground">{label}</span><span className="tnum text-sm font-semibold">{formatNumber(value as number | undefined)}</span></div>)}</>}</CardContent>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-[2fr_3fr]">
        <Card className="min-w-0">
          <CardHeader className="flex-row items-center justify-between"><div><CardTitle>Recent scans</CardTitle><p className="mt-1 text-xs text-muted-foreground">Latest discovery jobs in this scope.</p></div><Link href="/scans" className="text-xs text-primary hover:underline">View all</Link></CardHeader>
          <CardContent className="p-0">
            {recentScans.length ? <div className="divide-y">{recentScans.map((scan) => <Link key={scan.id} href={`/scans?scan=${scan.id}`} className="block px-4 py-3 transition-colors hover:bg-muted/30">
              <div className="grid min-w-0 grid-cols-[minmax(0,1fr)_auto] items-center gap-3">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium">{truncate(scan.target || "Untitled target", 42)}</p>
                  <p className="mt-1 truncate text-[11px] text-muted-foreground"><span>{titleCase(scan.source_type || "source")}</span><span> · Created {formatDate(scan.created_at)}</span></p>
                </div>
                <StatusBadge status={scan.status} className="shrink-0 p-2 self-center leading-none" />
              </div>
            </Link>)}</div> : <div className="p-5"><EmptyState title="No scans in this scope" description="Start discovery to create the first asset inventory." action={<Link href="/scans" className={buttonVariants({ size: "sm" })}>Start discovery <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" /></Link>} /></div>}
          </CardContent>
        </Card>
        <Card className="min-w-0">
          <CardHeader className="flex-row items-center justify-between"><div><CardTitle>Migration priorities</CardTitle><p className="mt-1 text-xs text-muted-foreground">Assets ranked by the current vulnerability and key-size signals.</p></div><Link href="/analysis" className="text-xs text-primary hover:underline">Risk analysis <ArrowRight className="ml-1 inline h-3 w-3" aria-hidden="true" /></Link></CardHeader>
          <CardContent className="p-0">
            {priorities.length ? <Table className="table-fixed"><TableHeader><TableRow><TableHead className="w-[36%] whitespace-normal px-3">Asset</TableHead><TableHead className="w-[16%] whitespace-normal px-3">Algorithm</TableHead><TableHead className="w-[14%] whitespace-normal px-3">Risk</TableHead><TableHead className="w-[34%] whitespace-normal px-3">Replacement</TableHead></TableRow></TableHeader><TableBody>{priorities.map((row) => <TableRow key={`${row.asset.id}-${row.score}`}><TableCell className="min-w-0 px-3"><p className="truncate font-medium" title={row.asset.name}>{row.asset.name}</p><p className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground" title={row.asset.location || "No location reported"}>{truncate(row.asset.location || "No location reported", 46)}</p></TableCell><TableCell className="min-w-0 px-3"><span className="block truncate font-mono text-xs" title={row.asset.algorithm || row.asset.family || "Unknown"}>{row.asset.algorithm || row.asset.family || "Unknown"}</span><span className="mt-0.5 block truncate text-[11px] text-muted-foreground">{row.asset.key_size ? `${row.asset.key_size} bits` : ""}</span></TableCell><TableCell className="px-3">{riskBadge(row.risk_label)}</TableCell><TableCell className="min-w-0 px-3"><p className="truncate text-xs text-muted-foreground" title={row.replacement}>{row.replacement}</p></TableCell></TableRow>)}</TableBody></Table> : <div className="p-5"><EmptyState title="No migration priorities" description="No vulnerable or weak assets are currently identified in this scope." /></div>}
          </CardContent>
        </Card>
      </div>

      <Dialog variant="dark" className="max-w-3xl ring-1 ring-white/10" open={processOpen} onOpenChange={setProcessOpen} title="How the ECDAT workflow works" description="The active scope moves through these platform stages as discovery, analysis, mitigation, and reporting data becomes available.">
        <div className="space-y-4">
          <SectionLabel className="text-white/60">Process stages</SectionLabel>
          {workflow.length ? <div className="divide-y divide-white/10 border-y border-white/10">{workflow.map((stage, index) => <div key={stage.key} className="flex gap-3 py-4 first:pt-3 last:pb-3"><div className={`mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center border text-[10px] font-semibold ${stage.done ? "border-white/30 bg-white/10 text-white" : "border-white/15 text-white/60"}`}>{stage.done ? <Check className="h-3.5 w-3.5" aria-hidden="true" /> : String(index + 1).padStart(2, "0")}</div><div className="min-w-0 flex-1"><div className="flex items-center justify-between gap-3"><p className="text-sm font-medium text-white">{stage.name}</p><span className="tnum text-xs text-white/60">{formatNumber(stage.count)}</span></div><p className="mt-1 text-xs leading-5 text-white/60">{stage.detail}</p>{stage.sub?.length ? <div className="mt-2 flex flex-wrap gap-1.5">{stage.sub.map((item) => <span key={item.label} className="border border-white/15 bg-white/5 px-1.5 py-0.5 text-[10px] text-white/65">{item.label} {formatNumber(item.count)}</span>)}</div> : null}{stage.api ? <Link href={stage.api} onClick={() => setProcessOpen(false)} className="mt-2 inline-flex items-center gap-1 text-xs text-white underline underline-offset-4 hover:text-white/80">Open {stage.name}<ArrowRight className="h-3 w-3" aria-hidden="true" /></Link> : null}</div></div>)}</div> : <EmptyState title="Workflow data unavailable" description="Process stage information is not available for this scope." />}
          <p className="text-[11px] leading-5 text-white/50">Each stage links to the page where you can act on it. Nothing here is inferred — counts come from what discovery has actually recorded.</p>
        </div>
      </Dialog>
    </div>
  );
}
