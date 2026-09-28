"use client";

import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { Activity, AlertTriangle, Clock3, Filter, Loader2, ScanLine, Search, Trash2, UserRound } from "lucide-react";
import { RefreshButton } from "@/components/ui/refresh-button";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
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
  const { ready, scopeKey, info, activeId, switchSession, refresh } = useSession();
  const { pushToast } = useToast();
  const router = useRouter();
  const queryClient = useQueryClient();

  const [limit, setLimit] = useState("200");
  const [search, setSearch] = useState("");
  const [opening, setOpening] = useState<number | null>(null);

  // Deletion modals state
  const [clearAllOpen, setClearAllOpen] = useState(false);
  const [clearingAll, setClearingAll] = useState(false);

  const [sessionToDelete, setSessionToDelete] = useState<{ id: number; name: string } | null>(null);
  const [deletingSession, setDeletingSession] = useState(false);

  const [jobToDelete, setJobToDelete] = useState<{ id: number; target: string } | null>(null);
  const [deletingJob, setDeletingJob] = useState(false);

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

  const handleClearAllHistory = async () => {
    setClearingAll(true);
    try {
      await api.clearAllScanHistory();
      await queryClient.invalidateQueries();
      await refresh();
      setClearAllOpen(false);
      pushToast("Entire scan history and workspace data cleared successfully.", "success");
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to clear scan history.", "error");
    } finally {
      setClearingAll(false);
    }
  };

  const handleDeleteSession = async () => {
    if (!sessionToDelete) return;
    setDeletingSession(true);
    try {
      await api.deleteScanHistory(sessionToDelete.id);
      await queryClient.invalidateQueries();
      await refresh();
      setSessionToDelete(null);
      pushToast(`Scan “${sessionToDelete.name}” deleted successfully.`, "success");
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to delete scan.", "error");
    } finally {
      setDeletingSession(false);
    }
  };

  const handleDeleteJob = async () => {
    if (!jobToDelete) return;
    setDeletingJob(true);
    try {
      await api.deleteScan(jobToDelete.id);
      await queryClient.invalidateQueries();
      setJobToDelete(null);
      pushToast(`Discovery job #${jobToDelete.id} deleted.`, "success");
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to delete discovery job.", "error");
    } finally {
      setDeletingJob(false);
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
              One entry per scan session. Manage past runs, switch scopes, or remove unwanted scan data.
            </p>
          </div>
          <div className="flex items-center gap-2">
            {history.data?.sessions.length ? (
              <Button
                variant="outline"
                size="sm"
                className="border-destructive/30 text-destructive hover:bg-destructive/10 hover:text-destructive"
                onClick={() => setClearAllOpen(true)}
              >
                <Trash2 className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
                Clear Entire History
              </Button>
            ) : null}
            <RefreshButton onRefresh={() => void history.refetch()} aria-label="Refresh scan history" variant="ghost" />
          </div>
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
                    <div className="flex items-center gap-2 shrink-0">
                      <Button
                        variant={session.is_active ? "outline" : "secondary"}
                        size="sm"
                        disabled={opening === session.id}
                        onClick={() => void openScan(session.id, session.name)}
                      >
                        {opening === session.id ? "Opening\u2026" : session.is_active ? "Viewing" : "Open"}
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        className="text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
                        title="Delete this scan from history"
                        aria-label={`Delete scan ${session.name}`}
                        onClick={() => setSessionToDelete({ id: session.id, name: session.name })}
                      >
                        <Trash2 className="h-4 w-4" aria-hidden="true" />
                      </Button>
                    </div>
                  </div>

                  {session.scans.length ? (
                    <ul className="mt-3 space-y-1.5 border-l-2 border-border pl-3">
                      {session.scans.map((scan) => (
                        <li key={scan.id} className="flex flex-wrap items-center justify-between gap-2 text-[11px] rounded p-1 hover:bg-muted/40 transition-colors">
                          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 min-w-0">
                            <span className="tnum font-mono text-muted-foreground">job #{scan.id}</span>
                            <span className="text-muted-foreground">{titleCase(scan.source_type)}</span>
                            <StatusBadge status={scan.status} />
                            <span className="min-w-0 truncate font-mono text-muted-foreground" title={scan.target}>
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
                          </div>
                          <button
                            type="button"
                            className="text-muted-foreground/60 hover:text-destructive p-1 rounded transition-colors"
                            title={`Delete job #${scan.id}`}
                            aria-label={`Delete job #${scan.id}`}
                            onClick={() => setJobToDelete({ id: scan.id, target: scan.target || `job #${scan.id}` })}
                          >
                            <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                          </button>
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

      <Card>
        <CardHeader className="flex-row flex-wrap items-end justify-between gap-3">
          <div>
            <CardTitle>Event history</CardTitle>
            <p className="mt-1 text-xs text-muted-foreground">Search filters the currently loaded events.</p>
          </div>
          <div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row">
            <div className="relative sm:w-64">
              <Search className="pointer-events-none absolute left-3 top-3 h-4 w-4 text-muted-foreground" aria-hidden="true" />
              <Input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Filter returned events" className="pl-9" aria-label="Filter audit events" />
            </div>
            <Select value={limit} onChange={(event) => setLimit(event.target.value)} className="sm:w-36" aria-label="Audit result limit">
              <option value="50">Latest 50</option>
              <option value="200">Latest 200</option>
              <option value="500">Latest 500</option>
              <option value="1000">Latest 1000</option>
            </Select>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {query.isLoading ? (
            <div className="p-5">
              <LoadingState label="Loading audit history" />
            </div>
          ) : query.isError ? (
            <div className="p-5">
              <ErrorState message={query.error instanceof Error ? query.error.message : undefined} onRetry={() => void query.refetch()} />
            </div>
          ) : rows.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Action</TableHead>
                  <TableHead>Message</TableHead>
                  <TableHead>Actor</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Session</TableHead>
                  <TableHead>Timestamp</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((entry) => (
                  <TableRow key={entry.id}>
                    <TableCell>
                      <span className="font-mono text-[11px] text-primary">{entry.action || "unknown"}</span>
                    </TableCell>
                    <TableCell className="max-w-[420px] text-xs leading-5">{entry.message || "—"}</TableCell>
                    <TableCell>
                      <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
                        <UserRound className="h-3.5 w-3.5" aria-hidden="true" />
                        {entry.actor || "System activity"}
                      </span>
                    </TableCell>
                    <TableCell className="font-mono text-[11px] text-muted-foreground">
                      {entry.target_type || "—"}
                      {entry.target_id ? ` · ${entry.target_id}` : ""}
                    </TableCell>
                    <TableCell className="font-mono text-[11px] text-muted-foreground">
                      {entry.session_id ? `#${entry.session_id}` : "All"}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                      {formatDate(entry.created_at)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="p-5">
              <EmptyState title="No audit events" description="No audit entries match this active scope and local filter." />
            </div>
          )}
        </CardContent>
        <div className="flex justify-between border-t px-5 py-3 text-[11px] text-muted-foreground">
          <span>
            Showing {formatNumber(rows.length)} of {formatNumber(query.data?.count || 0)} returned
          </span>
          <span>{titleCase(info?.scope || "all")}</span>
        </div>
      </Card>

      {/* Clear All Confirmation Dialog */}
      <Dialog
        open={clearAllOpen}
        onOpenChange={setClearAllOpen}
        title="Clear Entire Scan History"
        description="Permanently delete all scans and data across the entire workspace."
        footer={
          <>
            <Button variant="ghost" onClick={() => setClearAllOpen(false)} disabled={clearingAll}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleClearAllHistory} disabled={clearingAll}>
              {clearingAll ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <Trash2 className="mr-1.5 h-3.5 w-3.5" />}
              Clear Everything
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <div className="flex items-start gap-3 rounded border border-destructive/30 bg-destructive/5 p-3 text-xs leading-relaxed text-destructive">
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" aria-hidden="true" />
            <div>
              <p className="font-semibold">Irreversible Action</p>
              <p className="mt-1 text-muted-foreground">
                This will delete all discovery runs, cryptographic assets, CBOM components, quantum risk assessments, mitigation migration waves, and audit logs.
              </p>
            </div>
          </div>
          <p className="text-xs text-muted-foreground">
            Are you sure you want to proceed? This cannot be undone.
          </p>
        </div>
      </Dialog>

      {/* Delete Specific Session Dialog */}
      <Dialog
        open={Boolean(sessionToDelete)}
        onOpenChange={(open) => { if (!open) setSessionToDelete(null); }}
        title={`Delete Scan “${sessionToDelete?.name}”`}
        description={`Scan #${sessionToDelete?.id}`}
        footer={
          <>
            <Button variant="ghost" onClick={() => setSessionToDelete(null)} disabled={deletingSession}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleDeleteSession} disabled={deletingSession}>
              {deletingSession ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <Trash2 className="mr-1.5 h-3.5 w-3.5" />}
              Delete Scan Data
            </Button>
          </>
        }
      >
        <div className="space-y-3 text-xs">
          <p className="leading-relaxed text-foreground">
            Are you sure you want to delete <span className="font-semibold text-primary">#{sessionToDelete?.id} ({sessionToDelete?.name})</span>?
          </p>
          <div className="rounded border border-warning/40 bg-warning/5 p-3 text-warning">
            <div className="flex gap-2">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <span>All discoveries, CBOM assets, risk analysis runs, and mitigation plans linked to this scan will be permanently purged.</span>
            </div>
          </div>
        </div>
      </Dialog>

      {/* Delete Single Scan Job Dialog */}
      <Dialog
        open={Boolean(jobToDelete)}
        onOpenChange={(open) => { if (!open) setJobToDelete(null); }}
        title={`Delete Discovery Job #${jobToDelete?.id}`}
        description="Remove individual scanner output"
        footer={
          <>
            <Button variant="ghost" onClick={() => setJobToDelete(null)} disabled={deletingJob}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleDeleteJob} disabled={deletingJob}>
              {deletingJob ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <Trash2 className="mr-1.5 h-3.5 w-3.5" />}
              Delete Job
            </Button>
          </>
        }
      >
        <div className="space-y-3 text-xs">
          <p className="leading-relaxed text-foreground">
            Delete discovery job <span className="font-semibold text-primary">#{jobToDelete?.id}</span> ({jobToDelete?.target}) and its recorded raw observations?
          </p>
        </div>
      </Dialog>
    </div>
  );
}

function AuditMetric({ label, value, icon: Icon, text = false }: { label: string; value?: number | string; icon: typeof Activity; text?: boolean }) { return <Card className="p-4"><div className="flex items-center justify-between"><p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{label}</p><Icon className="h-4 w-4 text-muted-foreground" aria-hidden="true" /></div><p className={`mt-3 text-xl font-semibold ${text ? "truncate text-sm" : "tnum"}`}>{typeof value === "number" ? formatNumber(value) : value || "—"}</p></Card>; }
