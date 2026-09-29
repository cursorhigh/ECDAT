"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Info,
  Laptop,
  MonitorCog,
  Palette,
  Radar,
  RotateCcw,
  Server,
  Trash2
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { Separator } from "@/components/ui/separator";
import { HealthCards } from "@/components/data/health-indicator";
import { PageHeader, SectionLabel } from "@/components/data/page-header";
import { SessionScope } from "@/components/layout/session-scope";
import { useToast } from "@/components/feedback/toast";
import { useSession } from "@/lib/session-context";
import { api } from "@/lib/api/client";
import { useTheme } from "@/lib/theme";
import { formatNumber } from "@/lib/utils";

export default function SettingsPage() {
  const { theme, setTheme } = useTheme();
  const { info, activeId, recentSessions, resetCurrentScope } = useSession();
  const { pushToast } = useToast();
  const [resetOpen, setResetOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [detailsOpen, setDetailsOpen] = useState(false);

  const reset = async () => {
    setBusy(true);
    try {
      await resetCurrentScope();
      setResetOpen(false);
      pushToast("This scan's data was deleted. The audit trail was kept.", "success");
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Delete failed.", "error");
    } finally {
      setBusy(false);
    }
  };

  const scanName = info?.session_name || (activeId ? `Scan #${activeId}` : "No scan selected");

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="System"
        title="Settings"
        description="Appearance, the scan you are working in, and how this deployment is running."
        actions={
          <Button variant="outline" size="sm" onClick={() => setDetailsOpen(true)}>
            <Info className="h-3.5 w-3.5" aria-hidden="true" />
            Environment details
          </Button>
        }
      />

      <div className="space-y-3">
        <SectionLabel>Runtime</SectionLabel>
        <HealthCards />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <Palette className="h-4 w-4 text-primary" aria-hidden="true" />
              Appearance
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-2">
              <ThemeOption
                active={theme === "dark"}
                label="Dark"
                description="For long analyst sessions"
                onClick={() => setTheme("dark")}
              />
              <ThemeOption
                active={theme === "light"}
                label="Light"
                description="Same layout, white surfaces"
                onClick={() => setTheme("light")}
              />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex-row items-center justify-between gap-3">
            <CardTitle className="flex items-center gap-2 text-sm">
              <Radar className="h-4 w-4 text-primary" aria-hidden="true" />
              Current scan
            </CardTitle>
            <SessionScope compact />
          </CardHeader>
          <CardContent className="space-y-2.5">
            <p className="text-xs leading-4 text-muted-foreground">
              Every view follows the scan you pick here. Scans never share data, so switching one changes
              what you are looking at everywhere.
            </p>
            <div className="grid grid-cols-3 gap-2">
              <Stat label="Scan" value={scanName} />
              <Stat label="Assets" value={formatNumber(info?.counts.assets)} />
              <Stat label="Findings" value={formatNumber(info?.counts.raw_findings)} />
            </div>
            {recentSessions.length ? (
              <div>
                <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                  Recent scans
                  <span className="tnum ml-1.5 font-normal normal-case tracking-normal">
                    {recentSessions.length}
                  </span>
                </p>
                {/*
                 * One scrolling line instead of a wrapped block.
                 *
                 * Scans of the same target are named identically apart from the
                 * trailing timestamp, so the full names repeated eight times and
                 * wrapped the card over several lines to say one thing. Each chip
                 * now leads with the part that actually differs -- the time -- and
                 * keeps the full name in a tooltip, so the row stays a single line
                 * however many scans are on record.
                 */}
                <div className="flex gap-1.5 overflow-x-auto pb-0.5">
                  {recentSessions.map((session) => {
                    const parts = session.name.split("·");
                    const stamp = parts.length > 1 ? parts[parts.length - 1].trim() : "";
                    const label = stamp || session.name;
                    return (
                      <span
                        key={session.id}
                        title={session.name}
                        className={`shrink-0 whitespace-nowrap border px-2 py-0.5 text-[11px] ${
                          session.id === activeId ? "border-primary bg-primary/5" : ""
                        }`}
                      >
                        {label}
                      </span>
                    );
                  })}
                </div>
              </div>
            ) : null}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <Trash2 className="h-4 w-4 text-primary" aria-hidden="true" />
            Delete data
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="text-sm font-medium">Delete this scan&rsquo;s data</p>
              <p className="mt-0.5 text-xs text-muted-foreground">
                Removes its findings, assets, risk and migration results. The audit trail is kept, so the
                deletion stays on record.
              </p>
            </div>
            <Button variant="outline" onClick={() => setResetOpen(true)} disabled={busy} className="shrink-0">
              Delete scan data
            </Button>
          </div>
          <Separator />
          <p className="text-[11px] leading-4 text-muted-foreground">
            Need to remove a single discovery job, or clear every scan at once? Use the{" "}
            <span className="text-foreground">dustbin in the top bar</span>, which lists each job and asks
            you to confirm.
          </p>
        </CardContent>
      </Card>

      <Dialog
        open={resetOpen}
        onOpenChange={setResetOpen}
        title="Delete this scan's data?"
        description={`Everything discovered under ${scanName} will be removed.`}
        footer={
          <>
            <Button variant="ghost" onClick={() => setResetOpen(false)} disabled={busy}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={() => void reset()} disabled={busy}>
              <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
              {busy ? "Deleting…" : "Delete and start fresh"}
            </Button>
          </>
        }
      >
        <div className="space-y-3 text-xs leading-5 text-muted-foreground">
          <p>This removes the scan&rsquo;s raw findings, assets, dependencies, risk assessments, migration
            plans and reports.</p>
          <p className="flex items-start gap-2 border border-success/30 bg-success/5 p-2.5 text-foreground">
            <Server className="mt-0.5 h-3.5 w-3.5 shrink-0 text-success" aria-hidden="true" />
            <span>
              The audit trail is append-only and is <span className="font-semibold">not</span> deleted. This
              action is recorded against the scan permanently.
            </span>
          </p>
        </div>
      </Dialog>

      <EnvironmentDetailsDialog open={detailsOpen} onOpenChange={setDetailsOpen} />
    </div>
  );
}

/**
 * Reference material, kept out of the main view.
 *
 * Connection topology, capability limits and the source registry are all things
 * an operator checks occasionally and never acts on, so they used to occupy
 * most of the page. They belong behind one deliberate click, which is what this
 * dialog is.
 */
function EnvironmentDetailsDialog({
  open,
  onOpenChange
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const { ready, scopeKey } = useSession();
  const registry = useQuery({
    queryKey: ["scanners", scopeKey],
    queryFn: api.scanners,
    enabled: ready && open
  });
  const scanners = registry.data?.scanners || [];
  const available = scanners.filter((scanner) => scanner.status === "available").length;
  const quickRoots = registry.data?.scopes?.quick?.roots || [];

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Environment details"
      description="Reference information. Nothing on this screen is a setting you can change here."
    >
      <div className="space-y-5 text-xs">
        <div>
          <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
            How this workspace is reached
          </p>
          <ul className="space-y-2">
            <DetailRow
              icon={Server}
              title="Service gateway"
              body="Requests go through the workspace gateway to the configured backend. The API key is added server-side and is never exposed to the browser."
            />
            <DetailRow
              icon={Laptop}
              title="Credentials"
              body="Service credentials stay outside the browser and are only attached when the backend requires them."
            />
            <DetailRow
              icon={MonitorCog}
              title="Folder selection"
              body="Native folder picking needs the desktop build. In the browser, use the built-in folder browser instead."
            />
          </ul>
        </div>

        <div>
          <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
            Discovery sources · {available} of {scanners.length} available
          </p>
          {registry.isLoading ? (
            <p className="text-muted-foreground">Loading source registry…</p>
          ) : registry.isError ? (
            <p className="text-destructive">The source registry could not be read.</p>
          ) : (
            <ul className="divide-y border">
              {scanners.map((scanner) => (
                <li key={scanner.id} className="flex items-center gap-3 py-2">
                  <span
                    className={`h-1.5 w-1.5 shrink-0 ${
                      scanner.status === "available" ? "bg-success" : "bg-muted-foreground/40"
                    }`}
                    aria-hidden="true"
                  />
                  <span className="min-w-0 flex-1 truncate">{scanner.name}</span>
                  {scanner.supported_artifacts?.length ? (
                    <span className="hidden max-w-[240px] truncate text-[10px] text-muted-foreground sm:inline">
                      {scanner.supported_artifacts.join(", ")}
                    </span>
                  ) : null}
                  <span className="shrink-0 font-mono text-[10px] text-muted-foreground">{scanner.version}</span>
                </li>
              ))}
            </ul>
          )}
          {quickRoots.length ? (
            <p className="mt-2 leading-4 text-muted-foreground">
              The standard scope reads {quickRoots.length} key location
              {quickRoots.length === 1 ? "" : "s"} on this machine, including the local certificate
              stores and the SSH, GnuPG, Docker, AWS and Azure key directories.
            </p>
          ) : null}
        </div>
      </div>
    </Dialog>
  );
}

function DetailRow({ icon: Icon, title, body }: { icon: typeof Server; title: string; body: string }) {
  return (
    <li className="flex items-start gap-2.5">
      <span className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center border bg-muted">
        <Icon className="h-3.5 w-3.5" aria-hidden="true" />
      </span>
      <span>
        <span className="block font-medium text-foreground">{title}</span>
        <span className="mt-0.5 block leading-4 text-muted-foreground">{body}</span>
      </span>
    </li>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="border p-2">
      <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{label}</p>
      <p className="mt-0.5 truncate text-sm font-medium" title={value}>
        {value}
      </p>
    </div>
  );
}

function ThemeOption({
  active,
  label,
  description,
  onClick
}: {
  active: boolean;
  label: string;
  description: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={`flex items-center justify-between gap-2 border p-3 text-left transition-colors ${
        active ? "border-primary bg-primary/5" : "hover:bg-secondary"
      }`}
    >
      <span className="min-w-0">
        <span className="block text-sm font-semibold">{label}</span>
        <span className="mt-0.5 block truncate text-[11px] text-muted-foreground">{description}</span>
      </span>
      <span
        className={`h-3 w-3 shrink-0 border ${active ? "border-primary bg-primary" : "bg-transparent"}`}
        aria-hidden="true"
      />
    </button>
  );
}
