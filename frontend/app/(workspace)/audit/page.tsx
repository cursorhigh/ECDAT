"use client";

import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { Search, ShieldCheck, UserRound } from "lucide-react";
import { RefreshButton } from "@/components/ui/refresh-button";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Select } from "@/components/ui/input";
import { Tabs } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState, ErrorState, LoadingState } from "@/components/feedback/data-state";
import { PageHeader } from "@/components/data/page-header";
import { StatusBadge } from "@/components/data/status-badge";
import { useToast } from "@/components/feedback/toast";
import { api } from "@/lib/api/client";
import { useSession } from "@/lib/session-context";
import { formatDate, formatNumber, titleCase, truncate } from "@/lib/utils";

/**
 * Two records, one page, kept apart on purpose.
 *
 * The audit log is the append-only event stream and is the tab you land on --
 * it is the part that must never change. The scan history is a navigational
 * list of sessions. Stacking both meant scrolling past one to reach the other,
 * and made a read-only record sit directly above a list of openable objects.
 */
export default function AuditPage() {
  const { ready, scopeKey, info, activeId, switchSession, refresh } = useSession();
  const { pushToast } = useToast();
  const router = useRouter();
  const queryClient = useQueryClient();

  const [tab, setTab] = useState("audit");
  const [limit, setLimit] = useState("200");
  const [scope, setScope] = useState<"session" | "all">("session");
  const [search, setSearch] = useState("");
  const [opening, setOpening] = useState<number | null>(null);

  const query = useQuery({ queryKey: ["audit", scopeKey, limit, scope], queryFn: () => api.audit(Number(limit), scope), enabled: ready });
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
    <div className="space-y-4">
      <PageHeader
        eyebrow="Governance"
        title="Audit trail"
        description="An append-only record of every scan and every action taken against it."
        actions={
          <RefreshButton
            onRefresh={() => {
              void query.refetch();
              void history.refetch();
            }}
          />
        }
      />

      <div className="flex items-center gap-2 border border-success/40 bg-success/5 px-3 py-1.5 text-[11px] text-muted-foreground">
        <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-success" aria-hidden="true" />
        <span>
          <span className="font-medium text-foreground">Read-only record.</span> Entries cannot be edited or
          deleted, here or in the database. Deleting a scan keeps its history and is itself logged.
        </span>
      </div>

      <Tabs
        value={tab}
        onValueChange={setTab}
        items={[
          { value: "audit", label: "Audit history", count: query.data?.count },
          { value: "scans", label: "Scan history", count: history.data?.count }
        ]}
      />

      {tab === "audit" ? (
        <Card>
          <CardHeader className="flex-row flex-wrap items-center justify-between gap-3 py-3">
            <CardTitle className="text-sm">
              {scope === "all" ? "All scans" : info?.session_name || "Active scan"}
              <span className="ml-2 font-normal text-muted-foreground">
                {scope === "all" ? "including deleted scans" : "events for this scan"}
              </span>
            </CardTitle>
            <div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row">
              <div className="relative sm:w-56">
                <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" aria-hidden="true" />
                <Input
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Filter events"
                  className="pl-9"
                  aria-label="Filter audit events"
                />
              </div>
              <Select
                value={scope}
                onChange={(event) => setScope(event.target.value as "session" | "all")}
                className="sm:w-40"
                aria-label="Audit scope"
              >
                <option value="session">Active scan only</option>
                <option value="all">All scans</option>
              </Select>
              <Select value={limit} onChange={(event) => setLimit(event.target.value)} className="sm:w-32" aria-label="Audit result limit">
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
                <ErrorState
                  message={query.error instanceof Error ? query.error.message : undefined}
                  onRetry={() => void query.refetch()}
                />
              </div>
            ) : rows.length ? (
              /*
               * The limit selector goes to 1,000 events, and nothing bounded the
               * height, so choosing it produced a page thousands of pixels tall with
               * the filters, the scope switch and the count footer all scrolled out
               * of reach -- you could not see or change the filter that produced the
               * list you were looking at. Capped, scrolls inside its own panel, with
               * the header sticky so the columns stay named.
               */
              <div className="max-h-[32rem] overflow-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="sticky top-0 z-10 bg-card" title="The event that was recorded, as a stable machine-readable code. The message beside it is the human-readable form of the same event.">Action</TableHead>
                    <TableHead className="sticky top-0 z-10 bg-card" title="What happened, in words. This is the free-text detail the action code refers to.">Message</TableHead>
                    <TableHead className="sticky top-0 z-10 bg-card" title="Who or what caused the event. Without authentication on the API this is a claimed actor, not a verified identity.">Actor</TableHead>
                    <TableHead className="sticky top-0 z-10 bg-card" title="The object the event acted on, as type and id -- for example an analysisrun with an id.">Target</TableHead>
                    <TableHead className="sticky top-0 z-10 bg-card" title="The scan the event belongs to. A scan marked deleted keeps its history here after the scan itself is removed.">Scan</TableHead>
                    <TableHead className="sticky top-0 z-10 bg-card" title="When the event was recorded, in your local time.">Timestamp</TableHead>
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
                          {entry.actor || "System"}
                        </span>
                      </TableCell>
                      <TableCell className="font-mono text-[11px] text-muted-foreground">
                        {entry.target_type || "—"}
                        {entry.target_id ? ` · ${entry.target_id}` : ""}
                      </TableCell>
                      <TableCell className="font-mono text-[11px] text-muted-foreground">
                        {entry.session_id ? (
                          `#${entry.session_id}`
                        ) : entry.session_name ? (
                          <span
                            className="inline-flex items-center gap-1.5"
                            title={`Scan "${entry.session_name}" has been deleted. Its history is preserved.`}
                          >
                            <span className="border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-medium text-amber-600 dark:text-amber-400">
                              deleted
                            </span>
                            <span className="max-w-[140px] truncate">{entry.session_name}</span>
                          </span>
                        ) : (
                          "All"
                        )}
                      </TableCell>
                      <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                        {formatDate(entry.created_at)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              </div>
            ) : (
              <div className="p-5">
                <EmptyState
                  title={search ? "No matching events" : "No audit events yet"}
                  description={
                    search
                      ? "No loaded events match that filter."
                      : scope === "all"
                        ? "Nothing has been recorded in this workspace yet."
                        : "Run a discovery scan to start the record."
                  }
                />
              </div>
            )}
          </CardContent>
          <div className="flex justify-between border-t px-4 py-2 text-[11px] text-muted-foreground">
            <span>
              Showing {formatNumber(rows.length)} of {formatNumber(query.data?.count || 0)} returned
            </span>
            <span>
              {history.data?.count ?? 0} scan{(history.data?.count ?? 0) === 1 ? "" : "s"} on record
            </span>
          </div>
        </Card>
      ) : (
        <Card>
          <CardHeader className="flex-row items-center justify-between gap-3 py-3">
            <CardTitle className="text-sm">
              Scans on record
              <span className="ml-2 font-normal text-muted-foreground">
                open one to point every view at it
              </span>
            </CardTitle>
            <RefreshButton
              onRefresh={() => void history.refetch()}
              aria-label="Refresh scan history"
              variant="ghost"
            />
          </CardHeader>
          <CardContent className="p-0">
            {history.isLoading ? (
              <div className="p-5">
                <LoadingState label="Loading scan history" />
              </div>
            ) : history.isError ? (
              <div className="p-5">
                <ErrorState
                  message={history.error instanceof Error ? history.error.message : undefined}
                  onRetry={() => void history.refetch()}
                />
              </div>
            ) : history.data?.sessions.length ? (
              /*
               * Same reasoning as the audit table, and worse here: every scan is
               * listed with all of its jobs nested underneath, so the height grows
               * with scans x jobs rather than scans alone. Bounded, with the
               * heading row kept outside so the panel still reads as a list of
               * scans rather than a wall of text.
               */
              <ul className="max-h-[32rem] divide-y overflow-auto">
                {history.data.sessions.map((session) => (
                  <li key={session.id} className="px-4 py-3">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div className="flex min-w-0 flex-wrap items-center gap-2">
                        <span className="tnum font-mono text-[11px] text-muted-foreground">#{session.id}</span>
                        <span className="truncate text-sm font-medium">{session.name}</span>
                        {session.is_active ? (
                          <span className="border border-primary/40 bg-primary/5 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.1em] text-primary">
                            Active
                          </span>
                        ) : null}
                        <span className="text-[11px] text-muted-foreground">
                          {formatDate(session.created_at)} · {session.scans.length}{" "}
                          {session.scans.length === 1 ? "job" : "jobs"}
                        </span>
                      </div>
                      <Button
                        variant={session.is_active ? "outline" : "secondary"}
                        size="sm"
                        disabled={opening === session.id}
                        onClick={() => void openScan(session.id, session.name)}
                      >
                        {opening === session.id ? "Opening…" : session.is_active ? "Viewing" : "Open"}
                      </Button>
                    </div>

                    {session.scans.length ? (
                      <ul className="mt-2 space-y-0.5 border-l-2 border-border pl-3">
                        {session.scans.map((scan) => (
                          <li
                            key={scan.id}
                            className="flex flex-wrap items-center gap-x-3 gap-y-1 py-0.5 text-[11px] text-muted-foreground"
                          >
                            <span className="tnum font-mono">job #{scan.id}</span>
                            <span>{titleCase(scan.source_type)}</span>
                            <StatusBadge status={scan.status} />
                            <span className="min-w-0 truncate font-mono" title={scan.target}>
                              {truncate(scan.target || "Connected scope", 60)}
                            </span>
                            <span className="tnum">{formatNumber(scan.findings_count)} findings</span>
                            {scan.items_skipped ? (
                              <span className="tnum text-amber-600 dark:text-amber-400">
                                {formatNumber(scan.items_skipped)} skipped
                              </span>
                            ) : null}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="mt-2 border-l-2 border-border pl-3 text-[11px] text-muted-foreground">
                        No jobs recorded in this scan.
                      </p>
                    )}
                  </li>
                ))}
              </ul>
            ) : (
              <div className="p-5">
                <EmptyState
                  title="No scans yet"
                  description="Run a discovery scan and it will be listed here."
                />
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
