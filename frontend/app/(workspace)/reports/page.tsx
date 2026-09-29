"use client";

import { useState } from "react";
import Link from "next/link";
import { useMutation, useQuery } from "@tanstack/react-query";
import { AlertTriangle, Archive, ArrowDownToLine, ArrowRight, FileJson, FileSpreadsheet, FileText, Loader2, Shield, ShieldAlert, ShieldCheck } from "lucide-react";
import { Button, buttonVariants } from "@/components/ui/button";
import { RefreshButton } from "@/components/ui/refresh-button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState, ErrorState, LoadingState } from "@/components/feedback/data-state";
import { Separator } from "@/components/ui/separator";
import { CbomExport } from "@/components/data/cbom-export";
import { PageHeader, SectionLabel } from "@/components/data/page-header";
import { useToast } from "@/components/feedback/toast";
import { api } from "@/lib/api/client";
import { useSession } from "@/lib/session-context";
import { formatDate, formatNumber, refetchAllOrThrow } from "@/lib/utils";

function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function decodeBase64(value: string) {
  const binary = window.atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

export default function ReportsPage() {
  const { ready, scopeKey, info , hasSession } = useSession();
  const { pushToast } = useToast();
  const [busy, setBusy] = useState<string | null>(null);
  const overview = useQuery({ queryKey: ["reports-overview", scopeKey], queryFn: api.reportingOverview, enabled: ready && hasSession });
  const pipeline = useQuery({ queryKey: ["reports-pipeline", scopeKey], queryFn: api.reportingPipeline, enabled: ready && hasSession });

  const download = async (path: string, filename: string) => {
    setBusy(path);
    try {
      const blob = await api.reportsBlob(path);
      saveBlob(blob, filename);
      pushToast(`${filename} downloaded.`, "success");
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Export failed.", "error");
    } finally {
      setBusy(null);
    }
  };

  const generateFull = useMutation({
    mutationFn: api.fullReport,
    onSuccess: (payload) => {
      try {
        const blob = new Blob([decodeBase64(payload.b64)], { type: payload.mime || "application/octet-stream" });
        saveBlob(blob, payload.filename || `ecdat-report.${payload.format || "pdf"}`);
        pushToast(`${payload.filename || "Full report"} generated and downloaded.`, "success");
      } catch (error) {
        pushToast(error instanceof Error ? error.message : "The generated report could not be decoded.", "error");
      }
    },
    onError: (error) => pushToast(error instanceof Error ? error.message : "Full report generation failed.", "error")
  });

  const refresh = async () => {
    await refetchAllOrThrow([overview, pipeline]);
  };

  const kpis = overview.data?.kpis;

  return (
    <div className="space-y-6">
      <PageHeader compact eyebrow="Reporting" title="Reports & CBOM" description="Export current-scope snapshots and reports. Each export is prepared when you request it." actions={<RefreshButton onRefresh={refresh} />} />

      <div className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <SectionLabel>Cryptographic Estate Posture &amp; Readiness</SectionLabel>
          <span className="text-xs text-muted-foreground">
            Reporting overview for {info?.session_name || "All data"}
          </span>
        </div>

        {overview.isLoading ? (
          <LoadingState label="Loading report overview" />
        ) : overview.isError ? (
          <ErrorState message={overview.error instanceof Error ? overview.error.message : undefined} onRetry={() => void overview.refetch()} />
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
            <ReportMetric
              label="Total Assets"
              value={kpis?.assets}
              subtext={`${formatNumber(overview.data?.analysis_assets || kpis?.assessed || 0)} Findings`}
              icon={Shield}
              tone="default"
            />
            <ReportMetric
              label="Quantum Vulnerable"
              value={kpis?.quantum_vuln}
              subtext={`${kpis?.quantum_vuln_pct ?? 0}% Estate`}
              icon={AlertTriangle}
              tone="warning"
            />
            <ReportMetric
              label="HNDL Exposure"
              value={kpis?.hndl_exposed}
              subtext={`${kpis?.hndl_exposed_pct ?? 0}% Threat`}
              icon={AlertTriangle}
              tone="orange"
            />
            <ReportMetric
              label="Legacy & Deprecated"
              value={kpis?.weak}
              subtext="Non-Compliant"
              icon={ShieldAlert}
              tone="danger"
            />
            <ReportMetric
              label="Post-Quantum Ready"
              value={kpis?.pqc_ready}
              subtext={`${kpis?.pqc_ready_pct ?? 0}% FIPS`}
              icon={ShieldCheck}
              tone="success"
            />
          </div>
        )}
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.2fr_0.8fr]"><Card><CardHeader><CardTitle>Export center</CardTitle><p className="mt-1 text-xs leading-5 text-muted-foreground">Downloads are prepared for the active scope and saved by this browser. No remote storage is required.</p></CardHeader><CardContent className="space-y-3"><ExportRow icon={FileJson} title="Asset snapshot" description="Structured JSON asset inventory." action="assets.json" filename="ecdat-assets.json" onDownload={download} busy={busy} /><ExportRow icon={FileSpreadsheet} title="Raw findings CSV" description="Raw discovery findings with ingestion metadata." action="raw.csv" filename="ecdat-raw.csv" onDownload={download} busy={busy} /><ExportRow icon={FileSpreadsheet} title="Normalized findings CSV" description="Canonical algorithm and library fields." action="normalized.csv" filename="ecdat-normalized.csv" onDownload={download} busy={busy} /><ExportRow icon={Archive} title="Assets CSV" description="Flat asset inventory for downstream workflows." action="assets.csv" filename="ecdat-assets.csv" onDownload={download} busy={busy} /><div className="flex flex-col gap-3 border border-primary/30 bg-primary/5 p-4 sm:flex-row sm:items-center"><div className="flex min-w-0 flex-1 items-start gap-3"><FileText className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden="true" /><div><p className="text-sm font-semibold">Full enterprise report</p><p className="mt-1 text-xs leading-5 text-muted-foreground">Generates a PDF when a document renderer is available; otherwise a single self-contained HTML file is provided with a notice.</p></div></div><Button onClick={() => generateFull.mutate()} disabled={generateFull.isPending} className="shrink-0">{generateFull.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" /> : <ArrowDownToLine className="h-3.5 w-3.5" aria-hidden="true" />}Generate report</Button></div>{generateFull.data?.render_error ? <p className="text-xs text-warning">Document rendering notice: {generateFull.data.render_error}</p> : null}</CardContent></Card><Card><CardHeader><CardTitle>Discovery coverage</CardTitle><p className="mt-1 text-xs text-muted-foreground">What each discovery stage currently holds, and which sources contributed.</p></CardHeader><CardContent className="p-0">{pipeline.isLoading ? <div className="p-5"><LoadingState label="Loading pipeline" /></div> : pipeline.isError ? <div className="p-5"><ErrorState message={pipeline.error instanceof Error ? pipeline.error.message : undefined} onRetry={() => void pipeline.refetch()} /></div> : pipeline.data?.stages?.length ? <Table><TableHeader><TableRow><TableHead>Stage</TableHead><TableHead>Count</TableHead><TableHead>Breakdown</TableHead><TableHead>State</TableHead></TableRow></TableHeader><TableBody>{pipeline.data.stages.map((stage) => <TableRow key={stage.key}><TableCell><p className="font-medium">{stage.name}</p><p className="mt-0.5 text-[11px] text-muted-foreground">{stage.detail}</p></TableCell><TableCell className="tnum">{formatNumber(stage.count)}</TableCell><TableCell>{stage.sub?.length ? <ul className="space-y-0.5">{stage.sub.map((item) => <li key={item.label} className="flex items-center justify-between gap-3 text-[11px]"><span className="text-muted-foreground">{item.label}</span><span className="tnum">{formatNumber(item.count)}</span></li>)}</ul> : <span className="text-[11px] text-muted-foreground">—</span>}</TableCell><TableCell><span className={stage.done ? "text-xs text-success" : "text-xs text-muted-foreground"}>{stage.done ? "Ready" : "No data"}</span></TableCell></TableRow>)}</TableBody></Table> : <div className="p-5"><EmptyState title="Pipeline unavailable" description="No pipeline stages are available for this scope." /></div>}</CardContent></Card></div>

      <Card><CardHeader className="flex-row items-center justify-between"><div><CardTitle>Cryptographic bill of materials</CardTitle><p className="mt-1 text-xs leading-5 text-muted-foreground">An inventory of every cryptographic asset in the current scope, with the algorithm, key size, library and location recorded for each. CycloneDX opens in most supply-chain tooling.</p></div><ShieldCheck className="h-4 w-4 text-primary" aria-hidden="true" /></CardHeader><CardContent className="space-y-4"><div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"><p className="max-w-2xl text-sm leading-6 text-muted-foreground">The export is built when you ask for it, so it always reflects the scope as it stands at that moment. Use the analysis page to narrow it to a single run.</p><Link href="/analysis" className={buttonVariants({ variant: "outline", size: "sm" })}>Open analysis<ArrowRight className="h-3.5 w-3.5" aria-hidden="true" /></Link></div><Separator /><div className="flex flex-col gap-2"><SectionLabel>Download the current scope</SectionLabel><CbomExport /></div></CardContent></Card>
    </div>
  );
}

function ReportMetric({
  label,
  value,
  subtext,
  icon: Icon,
  tone = "default"
}: {
  label: string;
  value?: number;
  subtext?: string;
  icon: typeof Shield;
  tone?: "default" | "danger" | "warning" | "info" | "success" | "orange" | "purple";
}) {
  const borderClass =
    tone === "purple"
      ? "border-purple-500/35"
      : tone === "orange"
      ? "border-orange-500/35"
      : tone === "danger"
      ? "border-destructive/35"
      : tone === "warning"
      ? "border-amber-500/35"
      : tone === "info"
      ? "border-blue-500/35"
      : tone === "success"
      ? "border-emerald-500/35"
      : "";

  const iconClass =
    tone === "purple"
      ? "text-purple-500"
      : tone === "orange"
      ? "text-orange-500"
      : tone === "danger"
      ? "text-destructive"
      : tone === "warning"
      ? "text-amber-500"
      : tone === "info"
      ? "text-blue-400"
      : tone === "success"
      ? "text-emerald-500"
      : "text-primary";

  return (
    <Card className={`p-4 ${borderClass} flex flex-col justify-between`}>
      <div className="flex items-center justify-between">
        <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{label}</p>
        <Icon className={`h-4 w-4 ${iconClass}`} aria-hidden="true" />
      </div>
      <div className="mt-3 flex items-baseline justify-between gap-2">
        <p className="tnum truncate text-2xl font-semibold">{formatNumber(value)}</p>
        {subtext ? (
          <span className="text-[10px] font-mono font-medium text-muted-foreground whitespace-nowrap bg-muted/60 px-1.5 py-0.5 rounded border border-border/40">
            {subtext}
          </span>
        ) : null}
      </div>
    </Card>
  );
}

function ExportRow({ icon: Icon, title, description, action, filename, onDownload, busy }: { icon: typeof FileJson; title: string; description: string; action: string; filename: string; onDownload: (action: string, filename: string) => Promise<void>; busy: string | null }) {
  return <div className="flex flex-col gap-3 border p-4 sm:flex-row sm:items-center"><div className="flex min-w-0 flex-1 items-start gap-3"><Icon className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" /><div><p className="text-sm font-semibold">{title}</p><p className="mt-1 text-xs text-muted-foreground">{description}</p></div></div><Button variant="outline" size="sm" onClick={() => void onDownload(`/reports/${action}`, filename)} disabled={busy === `/reports/${action}`}>{busy === `/reports/${action}` ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" /> : <ArrowDownToLine className="h-3.5 w-3.5" aria-hidden="true" />}Download</Button></div>;
}
