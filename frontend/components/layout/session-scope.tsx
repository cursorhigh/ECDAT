"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { Check, ChevronDown, FolderKanban, Plus, RefreshCw, ScanLine } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Input, Label } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/components/feedback/toast";
import { api } from "@/lib/api/client";
import { useSession } from "@/lib/session-context";
import { cn } from "@/lib/utils";

/**
 * Picks which scan's session is active.
 *
 * There is deliberately no "all data" option. Each scan owns its own session and
 * nothing mixes, so the only choice here is *which* scan you are looking at. The
 * list comes from the server rather than browser memory, so an older scan is
 * still reachable after a restart; the audit page carries the full history.
 */
export function SessionScope({ compact = false }: { compact?: boolean }) {
  const { info, activeId, loading, error, createSession, switchSession, adoptSession } = useSession();
  const { pushToast } = useToast();
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);

  const history = useQuery({
    queryKey: ["scan-history"],
    queryFn: () => api.scanHistory(100),
    enabled: open
  });

  const run = async (action: () => Promise<void>, success: string) => {
    setBusy(true);
    try {
      await action();
      pushToast(success, "success");
      setOpen(false);
    } catch (actionError) {
      pushToast(actionError instanceof Error ? actionError.message : "Session action failed.", "error");
    } finally {
      setBusy(false);
    }
  };

  const choose = async (id: number, name: string) => {
    await run(async () => {
      if (id === activeId) {
        await adoptSession(id, name);
      } else {
        await switchSession(id);
      }
    }, `Now viewing “${name}”.`);
    // Everything on the page is scoped to the session, so it has to re-read.
    router.refresh();
  };

  const create = async () => {
    if (!name.trim()) return;
    await run(() => createSession(name.trim()), `Session “${name.trim()}” is active.`);
    setName("");
    setCreateOpen(false);
    router.refresh();
  };

  return (
    <>
      <div className="relative">
        <Button
          type="button"
          variant="outline"
          className={cn("h-9 justify-between gap-2", compact ? "max-w-[190px] px-2.5" : "min-w-[220px]")}
          onClick={() => setOpen((value) => !value)}
          aria-expanded={open}
          aria-haspopup="menu"
        >
          <span className="flex min-w-0 items-center gap-2">
            <ScanLine className="h-3.5 w-3.5 shrink-0 text-primary" aria-hidden="true" />
            <span className="min-w-0 truncate text-left text-xs">
              {loading ? "Loading…" : info?.session_name || "No scan selected"}
            </span>
          </span>
          <ChevronDown className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
        </Button>
        {open ? (
          <div className="absolute right-0 top-11 z-50 max-h-[70vh] w-80 overflow-y-auto border bg-popover p-2 text-popover-foreground shadow-2xl" role="menu">
            <div className="px-2 py-2">
              <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                Active scan
              </p>
              <p className="mt-1 text-sm font-medium">Everything on screen belongs to this scan alone.</p>
            </div>
            <Separator />
            {history.isLoading ? (
              <p className="px-2 py-3 text-xs text-muted-foreground">Loading scans…</p>
            ) : history.isError ? (
              <p className="px-2 py-3 text-xs text-destructive">Unable to load the scan list.</p>
            ) : history.data?.sessions.length ? (
              <ul className="mt-1">
                {history.data.sessions.map((session) => (
                  <li key={session.id}>
                    <button
                      type="button"
                      role="menuitem"
                      className="flex w-full items-center gap-2 px-2 py-2 text-left text-sm hover:bg-secondary disabled:opacity-50"
                      onClick={() => void choose(session.id, session.name)}
                      disabled={busy}
                    >
                      <FolderKanban className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate">{session.name}</span>
                        <span className="block text-[11px] text-muted-foreground">
                          {session.scans.length
                            ? session.scans
                                .map((scan) => `${scan.source_type.replace(/_/g, " ")} · ${scan.status}`)
                                .join(", ")
                            : "No scans recorded"}
                        </span>
                      </span>
                      <span className="tnum shrink-0 text-[10px] text-muted-foreground">#{session.id}</span>
                      {session.is_active ? <Check className="h-4 w-4 shrink-0 text-primary" aria-hidden="true" /> : null}
                    </button>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="px-2 py-3 text-xs text-muted-foreground">
                No scans recorded yet. Start one from the Scan page.
              </p>
            )}
            <Separator className="my-2" />
            <Button
              type="button"
              variant="secondary"
              size="sm"
              className="w-full justify-start"
              onClick={() => {
                setOpen(false);
                setCreateOpen(true);
              }}
            >
              <Plus className="h-3.5 w-3.5" aria-hidden="true" />
              New empty session
            </Button>
            <p className="mt-2 px-2 text-[11px] leading-4 text-muted-foreground">
              A new scan always creates its own session, so nothing needs setting up first.
            </p>
            {error ? <p className="mt-2 px-2 text-[11px] leading-4 text-destructive">{error}</p> : null}
          </div>
        ) : null}
      </div>
      <Dialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        title="Create an empty session"
        description="Useful when you want to ingest external findings before scanning."
      >
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="session-name">Session name</Label>
            <Input
              id="session-name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="e.g. Vendor-supplied findings"
              maxLength={128}
              autoFocus
            />
            <p className="text-[11px] leading-4 text-muted-foreground">
              It stays empty until you scan or ingest into it.
            </p>
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button onClick={() => void create()} disabled={!name.trim() || busy}>
              {busy ? (
                <RefreshCw className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
              ) : (
                <Plus className="h-3.5 w-3.5" aria-hidden="true" />
              )}
              Create and activate
            </Button>
          </div>
        </div>
      </Dialog>
    </>
  );
}
