"use client";

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { Activity, Clock3, Filter, ScanLine, Search, UserRound } from "lucide-react";
import { RefreshButton } from "@/components/ui/refresh-button";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Select } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState, ErrorState, LoadingState } from "@/components/feedback/data-state";
import { PageHeader, SectionLabel } from "@/components/data/page-header";
import { StatusBadge } from "@/components/data/status-badge";
import { useToast } from "@/components/feedback/toast";
import { api } from "@/lib/api/client";
import { useSession } from "@/lib/session-context";
import { formatDate, formatNumber, titleCase, truncate } from "@/lib/utils";

export default function AuditPage() {
  const { ready, scopeKey, info, activeId, switchSession } = useSession();
  const { pushToast } = useToast();
  const router = useRouter();
  const [limit, setLimit] = useState("200");
  const [search, setSearch] = useState("");
  const [opening, setOpening] = useState<number | null>(null);
  const query = useQuery({ queryKey: ["audit", scopeKey, limit], queryFn: () => api.audit(Number(limit)), enabled: ready });
  // The one cross-session view. Every scan owns its own session, so listing
  // sessions is listing scans; this replaced the History tab on the scans page.
  const history = useQuery({ queryKey: ["scan-history"], queryFn: () => api.scanHistory(100), enabled: ready });
  const rows = useMemo(() => {
    const value = search.trim().toLowerCase();
    return (query.data?.entries || []).filter((entry) => !value || [entry.action, entry.message, entry.actor, entry.target_type, entry.target_id].some((field) => String(field || "").includes(value)));
  }, [query.data?.entries, search]);

  const openScan = async (id: number, name: string) => {
    setOpening(id);
    try {
      if (id !== activeId) await switchSession(id);
      pushToast(`Now viewing “${name}”.`, "success");
      router.push("/scans");
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Unable to open that scan.", "error");
    } finally {
      setOpening(null);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Governance segment" title="Audit trail" description="Every scan that has been run, and the activity recorded against the active one. Each scan is isolated in its own session, so opening one points every view at it." actions={<RefreshButton onRefresh={() => { void query.refetch(); void history.refetch(); }} />} />
      <Card>
        <CardHeader className="flex-row flex-wrap items-end justify-between gap-3">
          <div>
            <CardTitle>Scan history</CardTitle>
            <p className="mt-1 text-xs leading-5 text-muted-foreground">
              One entry per scan. This is the only view that spans sessions, because it has to be
              the place a previous scan is found.
            </p>
          </div>
          <RefreshButton onRefresh={() => void history.refetch()} aria-label="Refresh scan history" variant="ghost" />
        </CardHeader>
        <CardContent className="p-0">
          {history.isLoading ? (
            <div className="p-5">
              <LoadingState label="Loading scan history" />
            </div>
          ) : history.isError ? (
            <div className="p-5">
              <ErrorState message={history.error instanceof Error ? history.error.message : undefined} onRetry={() => void history.refetch()} />
            </div>
          ) : history.data?.sessions.length ? (
            <ul className="divide-y">
              {history.data.sessions.map((session) => (
                <li key={session.id} className="px-5 py-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="tnum font-mono text-[11px] text-muted-foreground">#{session.id}</span>
                        <span className="text-sm font-medium">{session.name}</span>
                        {session.is_active ? (
                          <span className="border border-primary/40 bg-primary/5 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.1em] text-primary">
                            Active
                          </span>
                        ) : null}
                      </div>
                      <p className="mt-1 text-[11px] text-muted-foreground">
                        {formatDate(session.created_at)} · {session.scans.length}{" "}
                        {session.scans.length === 1 ? "scan" : "scans"}
                      </p>
                    </div>
                    <Button
                      variant={session.is_active ? "outline" : "secondary"}
                      size="sm"
                      className="shrink-0"
                      disabled={opening === session.id}
                      onClick={() => void openScan(session.id, session.name)}
                    >
                      {opening === session.id ? "Opening\u2026" : session.is_active ? "Viewing" : "Open"}
                    </Button>
                  </div>

                  {session.scans.length ? (
                    <ul className="mt-3 space-y-1.5 border-l-2 border-border pl-3">
                      {session.scans.map((scan) => (
                        <li key={scan.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px]">
                          <span className="tnum font-mono text-muted-foreground">job #{scan.id}</span>
                          <span className="text-muted-foreground">{titleCase(scan.source_type)}</span>
                          <StatusBadge status={scan.status} />
                          <span className="min-w-0 flex-1 truncate font-mono text-muted-foreground" title={scan.target}>
                            {truncate(scan.target || "Connected scope", 60)}
                          </span>
                          <span className="tnum text-muted-foreground">
                            {formatNumber(scan.findings_count)} findings
                          </span>
                          {scan.items_skipped ? (
                            <span className="tnum text-amber-600 dark:text-amber-400">
                              {formatNumber(scan.items_skipped)} skipped
                            </span>
                          ) : null}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="mt-3 border-l-2 border-border pl-3 text-[11px] text-muted-foreground">
                      No scans recorded in this session.
                    </p>
                  )}
                </li>
              ))}
            </ul>
          ) : (
            <div className="p-5">
              <EmptyState title="No scans yet" description="Run a discovery scan and it will be listed here." />
            </div>
          )}
        </CardContent>
      </Card>

      <div className="grid gap-3 sm:grid-cols-3">
        <AuditMetric label="Scans recorded" value={history.data?.count} icon={ScanLine} />
        <AuditMetric label="Events returned" value={query.data?.count} icon={Activity} />
        <AuditMetric label="Active scan" value={info?.session_name || "None selected"} text icon={Clock3} />
      </div>
      <Card><CardHeader className="flex-row flex-wrap items-end justify-between gap-3"><div><CardTitle>Event history</CardTitle><p className="mt-1 text-xs text-muted-foreground">Search filters the currently loaded events.</p></div><div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row"><div className="relative sm:w-64"><Search className="pointer-events-none absolute left-3 top-3 h-4 w-4 text-muted-foreground" aria-hidden="true" /><Input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Filter returned events" className="pl-9" aria-label="Filter audit events" /></div><Select value={limit} onChange={(event) => setLimit(event.target.value)} className="sm:w-36" aria-label="Audit result limit"><option value="50">Latest 50</option><option value="200">Latest 200</option><option value="500">Latest 500</option><option value="1000">Latest 1000</option></Select></div></CardHeader><CardContent className="p-0">{query.isLoading ? <div className="p-5"><LoadingState label="Loading audit history" /></div> : query.isError ? <div className="p-5"><ErrorState message={query.error instanceof Error ? query.error.message : undefined} onRetry={() => void query.refetch()} /></div> : rows.length ? <Table><TableHeader><TableRow><TableHead>Action</TableHead><TableHead>Message</TableHead><TableHead>Actor</TableHead><TableHead>Target</TableHead><TableHead>Session</TableHead><TableHead>Timestamp</TableHead></TableRow></TableHeader><TableBody>{rows.map((entry) => <TableRow key={entry.id}><TableCell><span className="font-mono text-[11px] text-primary">{entry.action || "unknown"}</span></TableCell><TableCell className="max-w-[420px] text-xs leading-5">{entry.message || "—"}</TableCell><TableCell><span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground"><UserRound className="h-3.5 w-3.5" aria-hidden="true" />{entry.actor || "System activity"}</span></TableCell><TableCell className="font-mono text-[11px] text-muted-foreground">{entry.target_type || "—"}{entry.target_id ? ` · ${entry.target_id}` : ""}</TableCell><TableCell className="font-mono text-[11px] text-muted-foreground">{entry.session_id ? `#${entry.session_id}` : "All"}</TableCell><TableCell className="whitespace-nowrap text-xs text-muted-foreground">{formatDate(entry.created_at)}</TableCell></TableRow>)}</TableBody></Table> : <div className="p-5"><EmptyState title="No audit events" description="No audit entries match this active scope and local filter." /></div>}</CardContent><div className="flex justify-between border-t px-5 py-3 text-[11px] text-muted-foreground"><span>Showing {formatNumber(rows.length)} of {formatNumber(query.data?.count || 0)} returned</span><span>{titleCase(info?.scope || "all")}</span></div></Card>
    </div>
  );
}

function AuditMetric({ label, value, icon: Icon, text = false }: { label: string; value?: number | string; icon: typeof Activity; text?: boolean }) { return <Card className="p-4"><div className="flex items-center justify-between"><p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{label}</p><Icon className="h-4 w-4 text-muted-foreground" aria-hidden="true" /></div><p className={`mt-3 text-xl font-semibold ${text ? "truncate text-sm" : "tnum"}`}>{typeof value === "number" ? formatNumber(value) : value || "—"}</p></Card>; }
