"use client";

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Activity, Clock3, Filter, RefreshCw, Search, UserRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Select } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState, ErrorState, LoadingState } from "@/components/feedback/data-state";
import { PageHeader } from "@/components/data/page-header";
import { api } from "@/lib/api/client";
import { useSession } from "@/lib/session-context";
import { formatDate, formatNumber, titleCase } from "@/lib/utils";

export default function AuditPage() {
  const { ready, scopeKey, info } = useSession();
  const [limit, setLimit] = useState("200");
  const [search, setSearch] = useState("");
  const query = useQuery({ queryKey: ["audit", scopeKey, limit], queryFn: () => api.audit(Number(limit)), enabled: ready });
  const rows = useMemo(() => {
    const value = search.trim().toLowerCase();
    return (query.data?.entries || []).filter((entry) => !value || [entry.action, entry.message, entry.actor, entry.target_type, entry.target_id].some((field) => String(field || "").toLowerCase().includes(value)));
  }, [query.data?.entries, search]);

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Governance segment" title="Audit trail" description="Read-only operational history returned by the Django audit endpoint. Entries reflect the active scope; actor fields may be unavailable for API-key actions." actions={<Button variant="outline" size="sm" onClick={() => void query.refetch()}><RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />Refresh</Button>} />
      <div className="grid gap-3 sm:grid-cols-3"><AuditMetric label="Entries returned" value={query.data?.count} icon={Activity} /><AuditMetric label="Limit" value={Number(limit)} icon={Filter} /><AuditMetric label="Visible scope" value={info?.session_name || "All data"} text icon={Clock3} /></div>
      <Card><CardHeader className="flex-row flex-wrap items-end justify-between gap-3"><div><CardTitle>Event history</CardTitle><p className="mt-1 text-xs text-muted-foreground">Newest events first. Local search filters the current response only.</p></div><div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row"><div className="relative sm:w-64"><Search className="pointer-events-none absolute left-3 top-3 h-4 w-4 text-muted-foreground" aria-hidden="true" /><Input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Filter returned events" className="pl-9" aria-label="Filter audit events" /></div><Select value={limit} onChange={(event) => setLimit(event.target.value)} className="sm:w-36" aria-label="Audit result limit"><option value="50">Latest 50</option><option value="200">Latest 200</option><option value="500">Latest 500</option><option value="1000">Latest 1000</option></Select></div></CardHeader><CardContent className="p-0">{query.isLoading ? <div className="p-5"><LoadingState label="Loading audit history" /></div> : query.isError ? <div className="p-5"><ErrorState message={query.error instanceof Error ? query.error.message : undefined} onRetry={() => void query.refetch()} /></div> : rows.length ? <Table><TableHeader><TableRow><TableHead>Action</TableHead><TableHead>Message</TableHead><TableHead>Actor</TableHead><TableHead>Target</TableHead><TableHead>Session</TableHead><TableHead>Timestamp</TableHead></TableRow></TableHeader><TableBody>{rows.map((entry) => <TableRow key={entry.id}><TableCell><span className="font-mono text-[11px] text-primary">{entry.action || "unknown"}</span></TableCell><TableCell className="max-w-[420px] text-xs leading-5">{entry.message || "—"}</TableCell><TableCell><span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground"><UserRound className="h-3.5 w-3.5" aria-hidden="true" />{entry.actor || "API key / system"}</span></TableCell><TableCell className="font-mono text-[11px] text-muted-foreground">{entry.target_type || "—"}{entry.target_id ? ` · ${entry.target_id}` : ""}</TableCell><TableCell className="font-mono text-[11px] text-muted-foreground">{entry.session_id ? `#${entry.session_id}` : "All"}</TableCell><TableCell className="whitespace-nowrap text-xs text-muted-foreground">{formatDate(entry.created_at)}</TableCell></TableRow>)}</TableBody></Table> : <div className="p-5"><EmptyState title="No audit events" description="No audit entries match this active scope and local filter." /></div>}</CardContent><div className="flex justify-between border-t px-5 py-3 text-[11px] text-muted-foreground"><span>Showing {formatNumber(rows.length)} of {formatNumber(query.data?.count || 0)} returned</span><span>{titleCase(info?.scope || "all")}</span></div></Card>
    </div>
  );
}

function AuditMetric({ label, value, icon: Icon, text = false }: { label: string; value?: number | string; icon: typeof Activity; text?: boolean }) { return <Card className="p-4"><div className="flex items-center justify-between"><p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{label}</p><Icon className="h-4 w-4 text-muted-foreground" aria-hidden="true" /></div><p className={`mt-3 text-xl font-semibold ${text ? "truncate text-sm" : "tnum"}`}>{typeof value === "number" ? formatNumber(value) : value || "—"}</p></Card>; }
