"use client";

import { useState } from "react";
import { Check, ChevronDown, Database, FolderKanban, Plus, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Input, Label } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/components/feedback/toast";
import { useSession } from "@/lib/session-context";
import { cn } from "@/lib/utils";

export function SessionScope({ compact = false }: { compact?: boolean }) {
  const { info, activeId, recentSessions, loading, error, createSession, switchSession } = useSession();
  const { pushToast } = useToast();
  const [open, setOpen] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);

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

  const create = async () => {
    if (!name.trim()) return;
    await run(() => createSession(name.trim()), `Session “${name.trim()}” is active.`);
    setName("");
    setCreateOpen(false);
  };

  return (
    <>
      <div className="relative">
        <Button type="button" variant="outline" className={cn("h-9 justify-between gap-2", compact ? "max-w-[170px] px-2.5" : "min-w-[210px]")} onClick={() => setOpen((value) => !value)} aria-expanded={open} aria-haspopup="menu">
          <span className="flex min-w-0 items-center gap-2">
            {activeId ? <FolderKanban className="h-3.5 w-3.5 shrink-0 text-primary" aria-hidden="true" /> : <Database className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />}
            <span className="min-w-0 truncate text-left text-xs">{loading ? "Loading scope…" : info?.session_name || "All data"}</span>
          </span>
          <ChevronDown className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
        </Button>
        {open ? (
          <div className="absolute right-0 top-11 z-50 w-72 border bg-popover p-2 text-popover-foreground shadow-2xl" role="menu">
            <div className="px-2 py-2"><p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Active scope</p><p className="mt-1 text-sm font-medium">Every request is scoped to this workspace.</p></div>
            <Separator />
            <button type="button" role="menuitem" className="flex w-full items-center gap-2 px-2 py-2.5 text-left text-sm hover:bg-secondary" onClick={() => void run(() => switchSession(0), "Viewing all data.")} disabled={busy || !activeId}>
              <Database className="h-4 w-4 text-muted-foreground" aria-hidden="true" /><span className="flex-1">All data</span>{!activeId ? <Check className="h-4 w-4 text-primary" aria-hidden="true" /> : null}
            </button>
            {recentSessions.length ? <div className="mt-1"><p className="px-2 py-1 text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Recent sessions</p>{recentSessions.map((session) => <button key={session.id} type="button" role="menuitem" className="flex w-full items-center gap-2 px-2 py-2 text-left text-sm hover:bg-secondary" onClick={() => void run(() => switchSession(session.id), `Session “${session.name}” is active.`)} disabled={busy}><FolderKanban className="h-4 w-4 text-muted-foreground" aria-hidden="true" /><span className="min-w-0 flex-1 truncate">{session.name}</span><span className="tnum text-[10px] text-muted-foreground">#{session.id}</span>{activeId === session.id ? <Check className="h-4 w-4 text-primary" aria-hidden="true" /> : null}</button>)}</div> : null}
            <Separator className="my-2" />
            <Button type="button" variant="secondary" size="sm" className="w-full justify-start" onClick={() => { setOpen(false); setCreateOpen(true); }}><Plus className="h-3.5 w-3.5" aria-hidden="true" />New analysis session</Button>
            {error ? <p className="mt-2 px-2 text-[11px] leading-4 text-destructive">{error}</p> : null}
          </div>
        ) : null}
      </div>
      <Dialog open={createOpen} onOpenChange={setCreateOpen} title="Create analysis session" description="Use a distinct workspace for a new scan or investigation.">
        <div className="space-y-4">
          <div className="space-y-2"><Label htmlFor="session-name">Session name</Label><Input id="session-name" value={name} onChange={(event) => setName(event.target.value)} placeholder="e.g. Q3 platform review" maxLength={128} autoFocus /><p className="text-[11px] leading-4 text-muted-foreground">The active scope stays visible in the top bar and is sent as <span className="font-mono">X-ECDAT-Session</span>.</p></div>
          <div className="flex justify-end gap-2"><Button variant="ghost" onClick={() => setCreateOpen(false)}>Cancel</Button><Button onClick={() => void create()} disabled={!name.trim() || busy}>{busy ? <RefreshCw className="h-3.5 w-3.5 animate-spin" aria-hidden="true" /> : <Plus className="h-3.5 w-3.5" aria-hidden="true" />}Create and activate</Button></div>
        </div>
      </Dialog>
    </>
  );
}
