"use client";

import { useState } from "react";
import { Database, KeyRound, Laptop, LockKeyhole, MonitorCog, Palette, RotateCcw, Server, ShieldCheck, SlidersHorizontal, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { Separator } from "@/components/ui/separator";
import { HealthCards } from "@/components/data/health-indicator";
import { PageHeader, SectionLabel } from "@/components/data/page-header";
import { SessionScope } from "@/components/layout/session-scope";
import { useToast } from "@/components/feedback/toast";
import { useSession } from "@/lib/session-context";
import { useTheme } from "@/lib/theme";
import { formatNumber } from "@/lib/utils";

export default function SettingsPage() {
  const { theme, setTheme } = useTheme();
  const { info, activeId, recentSessions, resetCurrentScope, clearActiveSession } = useSession();
  const { pushToast } = useToast();
  const [resetOpen, setResetOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  const reset = async () => {
    setBusy(true);
    try {
      await resetCurrentScope();
      setResetOpen(false);
      pushToast("The active scope was reset and returned to All data.", "success");
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Reset failed.", "error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="System segment" title="Settings" description="Inspect runtime boundaries, choose a visual theme, and manage the active work session. Configuration is intentionally local and credential-safe." />
      <div className="space-y-3"><SectionLabel>Runtime health</SectionLabel><HealthCards /></div>
      <div className="grid gap-4 xl:grid-cols-2"><Card><CardHeader><CardTitle className="flex items-center gap-2"><Palette className="h-4 w-4 text-primary" aria-hidden="true" />Appearance</CardTitle><p className="mt-1 text-xs text-muted-foreground">Sharp edges, spacious layout, and high-contrast neutral surfaces.</p></CardHeader><CardContent><div className="grid gap-3 sm:grid-cols-2"><ThemeOption active={theme === "dark"} label="Dark workspace" description="Near-black surfaces for long analyst sessions." onClick={() => setTheme("dark")} /><ThemeOption active={theme === "light"} label="Light workspace" description="White surfaces with the same information hierarchy." onClick={() => setTheme("light")} /></div></CardContent></Card><Card><CardHeader><CardTitle className="flex items-center gap-2"><Laptop className="h-4 w-4 text-primary" aria-hidden="true" />Local transport</CardTitle><p className="mt-1 text-xs text-muted-foreground">How this browser build reaches the Django service.</p></CardHeader><CardContent className="space-y-4"><div className="flex items-center gap-3 border p-3"><div className="flex h-8 w-8 items-center justify-center border bg-muted"><Server className="h-4 w-4" aria-hidden="true" /></div><div><p className="text-sm font-medium">Next.js API proxy</p><p className="mt-1 font-mono text-[11px] text-muted-foreground">/api/backend/* → configured Django URL</p></div></div><div className="flex items-center gap-3 border p-3"><div className="flex h-8 w-8 items-center justify-center border bg-muted"><LockKeyhole className="h-4 w-4" aria-hidden="true" /></div><div><p className="text-sm font-medium">Privileged API key stays server-side</p><p className="mt-1 text-xs leading-5 text-muted-foreground">Set <span className="font-mono">ECDAT_API_KEY</span> on the host when the backend requires authentication. It is not exposed in the browser bundle.</p></div></div><div className="flex items-center gap-3 border p-3"><div className="flex h-8 w-8 items-center justify-center border bg-muted"><MonitorCog className="h-4 w-4" aria-hidden="true" /></div><div><p className="text-sm font-medium">Remote fonts and CDN assets</p><p className="mt-1 text-xs text-muted-foreground">Not required by this frontend; system font fallbacks are bundled through CSS.</p></div></div></CardContent></Card></div>

      <Card><CardHeader className="flex-row items-center justify-between"><div><CardTitle className="flex items-center gap-2"><Database className="h-4 w-4 text-primary" aria-hidden="true" />Session management</CardTitle><p className="mt-1 text-xs text-muted-foreground">Scope controls affect every page and are sent as an explicit session header.</p></div><SessionScope compact /></CardHeader><CardContent className="space-y-4"><div className="grid gap-3 sm:grid-cols-3"><SettingValue label="Active scope" value={activeId ? info?.session_name || `Session #${activeId}` : "All data"} /><SettingValue label="Session ID" value={activeId ? `#${activeId}` : "0 / all"} /><SettingValue label="Assets in scope" value={formatNumber(info?.counts.assets)} /></div><Separator /><div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"><div><p className="text-sm font-medium">Reset active scope</p><p className="mt-1 text-xs text-muted-foreground">Deletes discovery and analysis data for the active session. This cannot be undone.</p></div><Button variant="outline" onClick={() => setResetOpen(true)} disabled={busy}><Trash2 className="h-3.5 w-3.5" aria-hidden="true" />Reset scope</Button></div>{recentSessions.length ? <div><SectionLabel>Recent local scopes</SectionLabel><div className="mt-2 flex flex-wrap gap-2">{recentSessions.map((session) => <span key={session.id} className="border bg-muted/30 px-2.5 py-1.5 text-xs"><span className="font-medium">{session.name}</span><span className="ml-2 font-mono text-[10px] text-muted-foreground">#{session.id}</span></span>)}</div></div> : null}</CardContent></Card>

      <Card><CardHeader><CardTitle className="flex items-center gap-2"><SlidersHorizontal className="h-4 w-4 text-primary" aria-hidden="true" />Capability boundaries</CardTitle><p className="mt-1 text-xs text-muted-foreground">The current backend does not expose every diagnostic surface in the product specification.</p></CardHeader><CardContent className="grid gap-3 sm:grid-cols-2"><Capability label="Worker health" state="Unavailable" detail="No worker health endpoint is exposed by the current API." /><Capability label="Scanner/ruleset version" state="Unavailable" detail="Version metadata is not returned by the health endpoint." /><Capability label="Local AI/model status" state="Unavailable" detail="Optional model state is not exposed to the frontend." /><Capability label="CBOM export endpoint" state="Analysis document" detail="CBOM is returned inside analysis detail; inspect or export it there." /><Capability label="Filesystem picker" state="Browser limitation" detail="Native picker requires the desktop shell; browser mode uses the local backend browse endpoint." /><Capability label="API key storage" state="Safe boundary" detail="Automation credentials remain in the server-side proxy environment." /></CardContent></Card>

      <Dialog open={resetOpen} onOpenChange={setResetOpen} title="Reset active scope?" description="This permanently deletes discovery and analysis data for the selected session." footer={<><Button variant="ghost" onClick={() => setResetOpen(false)}>Cancel</Button><Button variant="destructive" onClick={() => void reset()} disabled={busy}><RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />{busy ? "Resetting…" : "Reset and return to All data"}</Button></>}><div className="flex gap-3 border border-destructive/30 bg-destructive/5 p-4 text-sm leading-6"><Trash2 className="mt-0.5 h-4 w-4 shrink-0 text-destructive" aria-hidden="true" /><p>This action cannot be undone. The backend will remove the active workspace and its associated findings. If you are viewing All data, it resets all sessions instead.</p></div></Dialog>
    </div>
  );
}

function ThemeOption({ active, label, description, onClick }: { active: boolean; label: string; description: string; onClick: () => void }) { return <button type="button" onClick={onClick} className={`border p-4 text-left transition-colors ${active ? "border-primary bg-primary/5" : "hover:bg-secondary"}`}><div className="flex items-center justify-between gap-2"><p className="text-sm font-semibold">{label}</p><span className={`h-3 w-3 border ${active ? "border-primary bg-primary" : "bg-transparent"}`} aria-hidden="true" /></div><p className="mt-2 text-xs leading-5 text-muted-foreground">{description}</p></button>; }
function SettingValue({ label, value }: { label: string; value: string }) { return <div className="border p-3"><p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{label}</p><p className="mt-2 truncate text-sm font-medium">{value}</p></div>; }
function Capability({ label, state, detail }: { label: string; state: string; detail: string }) { return <div className="border p-4"><div className="flex items-center justify-between gap-3"><p className="text-sm font-semibold">{label}</p><span className="border border-border bg-muted/40 px-2 py-1 text-[10px] uppercase tracking-[0.1em] text-muted-foreground">{state}</span></div><p className="mt-2 text-xs leading-5 text-muted-foreground">{detail}</p></div>; }
