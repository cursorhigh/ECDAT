"use client";

import { useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, ChevronDown, Loader2, ShieldCheck, Trash2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { NavTooltip } from "@/components/ui/nav-tooltip";
import { useToast } from "@/components/feedback/toast";
import { api } from "@/lib/api/client";
import { useDismissOnOutside } from "@/lib/use-dismiss";
import { useSession } from "@/lib/session-context";

/** What a given destructive action will remove. Drives the confirm dialog. */
type Target =
  | { kind: "session"; id: number; name: string; findings: number; jobs: number }
  | { kind: "all" };

/**
 * Destructive data actions, behind one dustbin in the top bar.
 *
 * Deletion lives here rather than on the audit page because the audit page is a
 * record of what happened -- putting a delete button next to the evidence invites
 * using it to launder history. Nothing here can touch the audit trail: the
 * backend refuses it, and every one of these actions writes a permanent
 * "scan_deleted" entry saying it happened.
 */
export function DangerMenu() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const { pushToast } = useToast();
  const { hasSession, info } = useSession();

  const [open, setOpen] = useState(false);
  const [target, setTarget] = useState<Target | null>(null);
  // Keyed to the open target so the "type DELETE" box always starts empty,
  // without a setState-in-effect to clear it.
  const [typed, setTyped] = useState<{ target: Target | null; value: string }>({ target: null, value: "" });
  const wrapRef = useRef<HTMLDivElement>(null);

  const history = useQuery({
    queryKey: ["scan-history", "danger-menu"],
    queryFn: () => api.scanHistory(100),
    enabled: open
  });

  // Close on outside click / Escape, the way a menu is expected to behave.
  // Shared with the scan switcher and the graph node search.
  useDismissOnOutside({ active: open, ref: wrapRef, onDismiss: () => setOpen(false) });

  const confirmText = typed.target === target ? typed.value : "";

  const sessions = history.data?.sessions || [];
  const totalFindings = sessions.reduce(
    (sum, session) => sum + session.scans.reduce((inner, scan) => inner + (scan.findings_count || 0), 0),
    0
  );

  const remove = useMutation({
    mutationFn: async (what: Target) => {
      if (what.kind === "session") return api.deleteScanHistory(what.id);
      return api.clearAllScanHistory();
    },
    onSuccess: async (_result, what) => {
      setTarget(null);
      setOpen(false);
      const label =
        what.kind === "session" ? `Scan "${what.name}" deleted.` : "All scans deleted.";
      pushToast(`${label} The audit trail was kept.`, "success");
      await queryClient.invalidateQueries();
      if (what.kind === "all" || (what.kind === "session" && what.id === info?.session_id)) {
        router.push("/dashboard");
      }
    },
    onError: (error) =>
      pushToast(error instanceof Error ? error.message : "Deletion failed.", "error")
  });

  const askToDelete = (what: Target) => {
    setOpen(false);
    setTarget(what);
  };

  const needsTyping = target?.kind === "all";
  const canConfirm = !needsTyping || confirmText.trim().toUpperCase() === "DELETE";

  const describe = (() => {
    if (!target) return { title: "", body: null as React.ReactNode, confirm: "Delete" };
    if (target.kind === "session") {
      return {
        title: `Delete scan "${target.name}"?`,
        confirm: "Delete this scan",
        body: (
          <>
            <p>
              This permanently removes <span className="font-semibold text-foreground">{target.jobs} discovery job{target.jobs === 1 ? "" : "s"}</span>{" "}
              and <span className="font-semibold text-foreground">{target.findings} raw finding{target.findings === 1 ? "" : "s"}</span> from this scan, along with every asset, dependency,
              risk assessment, migration plan and report derived from it.
            </p>
            <PreservedNote />
          </>
        )
      };
    }
    return {
      title: "Delete every scan?",
      confirm: "Delete everything",
      body: (
        <>
          <p>
            This permanently removes every scan in the workspace: all sessions,{" "}
            <span className="font-semibold text-foreground">{totalFindings} raw findings</span>, and every asset, dependency, risk assessment,
            migration plan and report derived from them.
          </p>
          <p className="mt-2">Type <span className="font-semibold text-foreground">DELETE</span> to confirm.</p>
          <PreservedNote />
        </>
      )
    };
  })();

  return (
    <div className="relative" ref={wrapRef}>
      <NavTooltip
        title="Delete data"
        description="Remove this scan, a single job, or all history. Each one asks you to confirm first."
        tone="destructive"
        disabled={open}
      >
        <Button
          type="button"
          variant="ghost"
          size="icon"
          onClick={() => setOpen((value) => !value)}
          aria-label="Data deletion options"
          aria-expanded={open}
          aria-haspopup="menu"
          className="text-muted-foreground hover:text-destructive"
        >
          <Trash2 className="h-4 w-4" aria-hidden="true" />
        </Button>
      </NavTooltip>

      {open ? (
        <div
          role="menu"
          className="absolute right-0 top-full z-50 mt-1 w-[300px] border bg-card p-1.5 shadow-lg"
        >
          <p className="px-2 py-1.5 text-[10px] font-semibold uppercase tracking-[0.08em] text-muted-foreground">
            Delete data
          </p>

          {hasSession && info?.session_id && info.session_name ? (
            <MenuItem
              label={`Delete current scan "${info.session_name}"`}
              hint={`${info.counts.scans} job${info.counts.scans === 1 ? "" : "s"} · ${info.counts.raw_findings} findings`}
              disabled={remove.isPending}
              onClick={() =>
                askToDelete({
                  kind: "session",
                  id: info.session_id!,
                  name: info.session_name!,
                  // From the session info itself, so the confirm copy is right
                  // even before the history query lands.
                  jobs: info.counts.scans,
                  findings: info.counts.raw_findings
                })
              }
            />
          ) : (
            <p className="px-2 py-1.5 text-[11px] text-muted-foreground">No scan selected.</p>
          )}

          <div className="mt-1 border-t pt-1">
            <MenuItem
              label="Delete every scan"
              hint={
                sessions.length
                  ? `${sessions.length} scan${sessions.length === 1 ? "" : "s"} in this workspace`
                  : "Every scan in this workspace"
              }
              danger
              disabled={remove.isPending || !sessions.length}
              onClick={() => askToDelete({ kind: "all" })}
            />
          </div>

          <p className="flex items-start gap-1.5 border-t px-2 pt-2 pb-1 text-[10px] leading-relaxed text-muted-foreground">
            <ShieldCheck className="mt-0.5 h-3 w-3 shrink-0 text-success" aria-hidden="true" />
            The audit trail cannot be deleted. Each action below is recorded permanently.
          </p>
        </div>
      ) : null}

      <Dialog
        open={Boolean(target)}
        onOpenChange={(value) => {
          if (!value) setTarget(null);
        }}
        title={describe.title}
        description="This cannot be undone."
        footer={
          <>
            <Button variant="ghost" onClick={() => setTarget(null)} disabled={remove.isPending}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => target && remove.mutate(target)}
              disabled={remove.isPending || !canConfirm}
            >
              {remove.isPending ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <Trash2 className="mr-1.5 h-3.5 w-3.5" />}
              {describe.confirm}
            </Button>
          </>
        }
      >
        <div className="space-y-3 text-xs leading-relaxed text-muted-foreground">
          {describe.body}
          {needsTyping ? (
            <input
              value={confirmText}
              onChange={(event) => setTyped({ target, value: event.target.value })}
              placeholder="DELETE"
              aria-label="Type DELETE to confirm"
              className="w-full border bg-background px-2.5 py-1.5 font-mono text-xs outline-none focus:border-destructive"
            />
          ) : null}
        </div>
      </Dialog>
    </div>
  );
}

function PreservedNote() {
  return (
    <p className="flex items-start gap-1.5 border border-success/30 bg-success/5 px-2.5 py-2 text-[11px] text-foreground">
      <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-success" aria-hidden="true" />
      <span>
        The audit trail is <span className="font-semibold">not</span> deleted. It is append-only, so this
        deletion is itself recorded and cannot be edited or removed afterwards.
      </span>
    </p>
  );
}

function MenuItem({
  label,
  hint,
  onClick,
  disabled,
  danger
}: {
  label: string;
  hint?: string;
  onClick: () => void;
  disabled?: boolean;
  danger?: boolean;
}) {
  return (
    <button
      type="button"
      role="menuitem"
      onClick={onClick}
      disabled={disabled}
      className={`block w-full px-2 py-1.5 text-left text-xs transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
        danger ? "text-destructive hover:bg-destructive/10" : "hover:bg-secondary"
      }`}
    >
      <span className="flex items-center gap-1.5 font-medium">
        <span className="min-w-0 flex-1 truncate">{label}</span>
        <ChevronDown className="h-3 w-3 -rotate-90 opacity-40" aria-hidden="true" />
      </span>
      {hint ? <span className="mt-0.5 block truncate text-[10px] font-normal text-muted-foreground">{hint}</span> : null}
    </button>
  );
}
