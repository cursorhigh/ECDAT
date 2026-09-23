"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { Activity, ArrowRight, Boxes, FileBarChart, Radar, ShieldAlert, Sparkles } from "lucide-react";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Button, buttonVariants } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { MetricCard } from "@/components/data/metric-card";
import { ErrorState, EmptyState, LoadingState } from "@/components/feedback/data-state";
import { PageHeader, SectionLabel } from "@/components/data/page-header";
import { StatusBadge, riskBadge } from "@/components/data/status-badge";
import { api } from "@/lib/api/client";
import { useSession } from "@/lib/session-context";
import { cn, formatDate, formatNumber, truncate } from "@/lib/utils";

const riskColors: Record<string, string> = {
  vulnerable: "hsl(var(--destructive))",
  weak: "hsl(var(--warning))",
  moderate: "hsl(35 85% 58%)",
  pqc: "hsl(var(--success))",
  unknown: "hsl(var(--muted-foreground))"
};

export default function DashboardPage() {
  const { ready, scopeKey, info } = useSession();
  const overview = useQuery({ queryKey: ["dashboard", "overview", scopeKey], queryFn: api.reportingOverview, enabled: ready });
  const stats = useQuery({ queryKey: ["dashboard", "stats", scopeKey], queryFn: api.stats, enabled: ready });
  const scans = useQuery({ queryKey: ["dashboard", "scans", scopeKey], queryFn: () => api.scans({ ordering: "created_at", page: 1 }), enabled: ready });

  const retry = () => {
    void overview.refetch();
    void stats.refetch();
    void scans.refetch();
  };

  if (overview.isLoading) return <LoadingState label="Loading estate posture" />;
  if (overview.isError) return <ErrorState message={overview.error instanceof Error ? overview.error.message : undefined} onRetry={retry} />;

  const data = overview.data;
  const kpis = data?.kpis;
  const riskData = data?.risk_split || [];
  const recentScans = scans.data?.results?.slice(0, 5) || [];
  const priorities = data?.vuln_priorities?.slice(0, 6) || [];

  return (
    <div className="space-y-6">
      <PageHeader eyebrow={info?.session_name || "Estate scope"} title="Security posture" description="A live view of discovered cryptographic assets, quantum exposure, and migration readiness in the active workspace." actions={<><Link href="/scans" className={buttonVariants({ variant: "outline", size: "sm" })}><Radar className="h-3.5 w-3.5" aria-hidden="true" />New scan</Link><Link href="/reports" className={buttonVariants({ size: "sm" })}><FileBarChart className="h-3.5 w-3.5" aria-hidden="true" />Reports</Link></>} />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Cryptographic assets" value={kpis?.assets} detail="Discovered in active scope" icon={Boxes} href="/assets" />
        <MetricCard label="Quantum-vulnerable" value={kpis?.quantum_vuln} detail={`${formatNumber(kpis?.quantum_vuln_pct || 0)}% of inventory`} icon={ShieldAlert} tone="danger" href="/analysis" />
        <MetricCard label="PQC-ready" value={kpis?.pqc_ready} detail={`${formatNumber(kpis?.pqc_ready_pct || 0)}% of inventory`} icon={Sparkles} tone="accent" />
        <MetricCard label="Scan coverage" value={kpis?.scans} detail={`${formatNumber(data?.scan_running || 0)} scan${data?.scan_running === 1 ? "" : "s"} running`} icon={Activity} href="/scans" />
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.05fr_1.4fr]">
        <Card>
          <CardHeader className="flex-row items-start justify-between"><div><CardTitle>Risk distribution</CardTitle><p className="mt-1 text-xs text-muted-foreground">Backend-classified assets, not frontend thresholds.</p></div><Link href="/assets" className="text-xs text-primary hover:underline">View assets</Link></CardHeader>
          <CardContent>
            {riskData.length ? <div className="h-[240px] w-full"><ResponsiveContainer width="100%" height="100%"><BarChart data={riskData} layout="vertical" margin={{ top: 4, right: 12, left: 4, bottom: 0 }}><CartesianGrid horizontal={false} stroke="hsl(var(--border))" /><XAxis type="number" allowDecimals={false} tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 11 }} /><YAxis type="category" dataKey="label" width={92} tick={{ fill: "hsl(var(--foreground))", fontSize: 11 }} axisLine={false} tickLine={false} /><Tooltip cursor={{ fill: "hsl(var(--muted))" }} contentStyle={{ background: "hsl(var(--popover))", border: "1px solid hsl(var(--border))", borderRadius: 0, color: "hsl(var(--popover-foreground))", fontSize: 12 }} /><Bar dataKey="count" radius={0} barSize={18}>{riskData.map((row) => <Cell key={row.key} fill={riskColors[row.key] || riskColors.unknown} />)}</Bar></BarChart></ResponsiveContainer></div> : <EmptyState title="No risk distribution yet" description="The reporting API returned no risk categories for this scope." />}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex-row items-start justify-between"><div><CardTitle>Readiness workflow</CardTitle><p className="mt-1 text-xs text-muted-foreground">The path from discovery to an enterprise report.</p></div><Link href="/analysis" className="text-xs text-primary hover:underline">Open analysis</Link></CardHeader>
          <CardContent>
            {data?.workflow?.length ? <div className="space-y-1">{data.workflow.map((stage, index) => <div key={stage.key} className="group flex gap-3 border-b py-3 last:border-0"><div className={cn("mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center border text-[10px] font-semibold", stage.done ? "border-success/40 bg-success/10 text-success" : "border-border text-muted-foreground")}>{stage.done ? "✓" : String(index + 1).padStart(2, "0")}</div><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center justify-between gap-2"><p className="text-sm font-medium">{stage.name}</p><span className="tnum text-xs text-muted-foreground">{formatNumber(stage.count)}</span></div><p className="mt-1 text-xs leading-5 text-muted-foreground">{stage.detail}</p>{stage.sub?.length ? <div className="mt-2 flex flex-wrap gap-1.5">{stage.sub.map((item) => <span key={item.label} className="border bg-muted/40 px-1.5 py-0.5 text-[10px] text-muted-foreground">{item.label} {formatNumber(item.count)}</span>)}</div> : null}</div></div>)}</div> : <EmptyState title="Workflow data unavailable" description="The reporting API did not return workflow stages." />}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.35fr_1fr]">
        <Card>
          <CardHeader className="flex-row items-center justify-between"><div><CardTitle>Recent scans</CardTitle><p className="mt-1 text-xs text-muted-foreground">Latest discovery jobs in this scope.</p></div><Link href="/scans" className="text-xs text-primary hover:underline">View all</Link></CardHeader>
          <CardContent className="p-0">{recentScans.length ? <Table><TableHeader><TableRow><TableHead>Target</TableHead><TableHead>Status</TableHead><TableHead>Created</TableHead></TableRow></TableHeader><TableBody>{recentScans.map((scan) => <TableRow key={scan.id}><TableCell><Link href={`/scans?scan=${scan.id}`} className="font-medium hover:text-primary">{truncate(scan.target || "Untitled target", 42)}</Link><p className="mt-0.5 text-[11px] text-muted-foreground">{scan.source_type || "source"}</p></TableCell><TableCell><StatusBadge status={scan.status} /></TableCell><TableCell className="whitespace-nowrap text-xs text-muted-foreground">{formatDate(scan.created_at)}</TableCell></TableRow>)}</TableBody></Table> : <div className="p-5"><EmptyState title="No scans in this scope" description="Start discovery to create the first asset inventory." action={<Link href="/scans" className={buttonVariants({ size: "sm" })}>Start discovery <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" /></Link>} /></div>}</CardContent>
        </Card>
        <Card>
          <CardHeader className="flex-row items-center justify-between"><div><CardTitle>Inventory facts</CardTitle><p className="mt-1 text-xs text-muted-foreground">Discovery pipeline counts.</p></div><Activity className="h-4 w-4 text-muted-foreground" aria-hidden="true" /></CardHeader>
          <CardContent className="space-y-3">{stats.isError ? <p className="text-xs text-destructive">Stats are unavailable for this scope.</p> : <>{[["Raw findings", stats.data?.raw_total], ["Normalized findings", stats.data?.normalized_total], ["Asset relations", stats.data?.relation_total], ["Audit events", stats.data?.audit_total]].map(([label, value]) => <div key={String(label)} className="flex items-center justify-between border-b pb-3 last:border-0 last:pb-0"><span className="text-sm text-muted-foreground">{label}</span><span className="tnum text-sm font-semibold">{formatNumber(value as number | undefined)}</span></div>)}</>}</CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="flex-row items-center justify-between"><div><CardTitle>Migration priorities</CardTitle><p className="mt-1 text-xs text-muted-foreground">Assets ranked by the backend’s vulnerability and key-size signals.</p></div><Link href="/analysis" className="text-xs text-primary hover:underline">Risk analysis <ArrowRight className="ml-1 inline h-3 w-3" aria-hidden="true" /></Link></CardHeader>
        <CardContent className="p-0">{priorities.length ? <Table><TableHeader><TableRow><TableHead>Asset</TableHead><TableHead>Algorithm</TableHead><TableHead>Risk</TableHead><TableHead>Replacement direction</TableHead></TableRow></TableHeader><TableBody>{priorities.map((row) => <TableRow key={`${row.asset.id}-${row.score}`}><TableCell><p className="font-medium">{row.asset.name}</p><p className="mt-0.5 max-w-[280px] truncate font-mono text-[11px] text-muted-foreground">{truncate(row.asset.location || "No location reported", 46)}</p></TableCell><TableCell><span className="font-mono text-xs">{row.asset.algorithm || row.asset.family || "Unknown"}</span><span className="ml-1 text-xs text-muted-foreground">{row.asset.key_size ? `${row.asset.key_size} bits` : ""}</span></TableCell><TableCell>{riskBadge(row.risk_label)}</TableCell><TableCell className="max-w-[300px] text-xs text-muted-foreground">{row.replacement}</TableCell></TableRow>)}</TableBody></Table> : <div className="p-5"><EmptyState title="No migration priorities" description="The reporting API returned no vulnerable or weak assets for this scope." /></div>}</CardContent>
      </Card>
    </div>
  );
}
