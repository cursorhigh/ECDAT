"use client";

import { ChangeEvent, FormEvent, useState } from "react";
import { useSearchParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, FileJson, Folder, FolderOpen, Loader2, Play, ScanLine, Upload, XCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { RefreshButton } from "@/components/ui/refresh-button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { Input, Label, Select, Textarea } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs } from "@/components/ui/tabs";
import { EmptyState, ErrorState, LoadingState } from "@/components/feedback/data-state";
import { PageHeader, SectionLabel } from "@/components/data/page-header";
import { StatusBadge } from "@/components/data/status-badge";
import { useToast } from "@/components/feedback/toast";
import { api } from "@/lib/api/client";
import type { ScanJob, StartScanPayload } from "@/lib/api/types";
import { useSession } from "@/lib/session-context";
import { formatDate, formatNumber, isTerminalStatus, titleCase, truncate } from "@/lib/utils";

const terminalStatuses = new Set(["completed", "complete", "failed", "cancelled", "canceled"]);

function joinPath(parent: string, child: string) {
  if (!parent) return child;
  return `${parent.replace(/[\\/]+$/, "")}\\${child}`;
}

export default function ScansPage() {
  const searchParams = useSearchParams();
  const { ready, scopeKey, adoptSession } = useSession();
  const { pushToast } = useToast();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState("local");
  const [scanType, setScanType] = useState<StartScanPayload["scan_type"]>("specified");
  const [target, setTarget] = useState("");
  const [maxFiles, setMaxFiles] = useState("10000");
  const [maxDepth, setMaxDepth] = useState("12");
  const [maxFileSize, setMaxFileSize] = useState("4194304");
  const [browseOpen, setBrowseOpen] = useState(false);
  const [browsePath, setBrowsePath] = useState("");
  const [reviewOpen, setReviewOpen] = useState(false);
  const [activeJob, setActiveJob] = useState<ScanJob | null>(null);
  const [externalName, setExternalName] = useState("");
  const [externalTarget, setExternalTarget] = useState("");
  const [externalJson, setExternalJson] = useState("");

  const scans = useQuery({ queryKey: ["scans", scopeKey], queryFn: () => api.scans({ ordering: "created_at", page: 1 }), enabled: ready });
  const preview = useQuery({ queryKey: ["scan-preview", scanType, scopeKey], queryFn: () => api.scanPreview(scanType), enabled: ready && scanType !== "specified" });
  const browse = useQuery({ queryKey: ["browse", browsePath, scopeKey], queryFn: () => api.browse(browsePath || undefined), enabled: ready && browseOpen });
  const requestedScanId = Number(searchParams.get("scan")) || null;
  const jobId = activeJob?.id || requestedScanId;
  const job = useQuery({ queryKey: ["scan-job", jobId, scopeKey], queryFn: () => api.scan(jobId!), enabled: Boolean(jobId), refetchInterval: (query) => terminalStatuses.has(String(query.state.data?.status || "").toLowerCase()) ? false : 3000 });

  const startScan = useMutation({
    mutationFn: async (payload: StartScanPayload) => api.startScan(payload),
    onSuccess: async (created) => {
      if (created.session) await adoptSession(created.session.id, created.session.name);
      setActiveJob(created);
      setReviewOpen(false);
      pushToast(`Scan #${created.id} started.`, "success");
      await queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
    onError: (error) => pushToast(error instanceof Error ? error.message : "Scan could not be started.", "error")
  });

  const demoScan = useMutation({
    mutationFn: api.demoScan,
    onSuccess: async (created) => {
      setActiveJob(created);
      pushToast(`Demo scan #${created.id} completed or is processing.`, "success");
      await queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
    onError: (error) => pushToast(error instanceof Error ? error.message : "Demo scan failed.", "error")
  });

  const cancelScan = useMutation({
    mutationFn: (id: number) => api.cancelScan(id),
    onSuccess: async () => { pushToast("Scan cancellation requested.", "info"); await queryClient.invalidateQueries({ queryKey: ["scans"] }); },
    onError: (error) => pushToast(error instanceof Error ? error.message : "Scan could not be cancelled.", "error")
  });

  const ingest = useMutation({
    mutationFn: async () => {
      let parsed: unknown;
      try { parsed = JSON.parse(externalJson); } catch { throw new Error("The findings file is not valid JSON."); }
      const payload = Array.isArray(parsed) ? { source_type: "source_code", target: externalTarget || externalName || "external-data", findings: parsed } : parsed;
      if (!payload || typeof payload !== "object" || !Array.isArray((payload as { findings?: unknown }).findings)) throw new Error("The JSON must contain a findings array.");
      return api.ingestScanData(payload as Record<string, unknown>);
    },
    onSuccess: async (created) => {
      if (created.session) await adoptSession(created.session.id, created.session.name);
      setActiveJob(created);
      pushToast(`External findings ingested into scan #${created.id}.`, "success");
      await queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
    onError: (error) => pushToast(error instanceof Error ? error.message : "External findings could not be ingested.", "error")
  });

  const reviewScan = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (scanType === "specified" && !target.trim()) { pushToast("Enter a folder path for a specified scan.", "error"); return; }
    setReviewOpen(true);
  };

  const confirmScan = () => {
    startScan.mutate({ scan_type: scanType, source_type: "source_code", target: target.trim(), options: { max_files: Number(maxFiles) || undefined, max_depth: Number(maxDepth) || undefined, max_file_size: Number(maxFileSize) || undefined } });
  };

  const readFile = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    setExternalName(file.name);
    const reader = new FileReader();
    reader.onload = () => setExternalJson(String(reader.result || ""));
    reader.onerror = () => pushToast("The findings file could not be read.", "error");
    reader.readAsText(file);
  };

  const previewRoots = preview.data?.roots || [];
  const currentJob = job.data || activeJob;
  const scanRows = scans.data?.results || [];

  return (
    <div className="space-y-6">
      <PageHeader compact eyebrow="Discovery segment" title="Discovery & scans" description="Create an isolated session, inspect a local folder, or ingest findings from an external discovery source. All job states reflect the current platform state." actions={<Button variant="outline" size="sm" onClick={() => demoScan.mutate()} disabled={demoScan.isPending}><Play className="h-3.5 w-3.5" aria-hidden="true" />{demoScan.isPending ? "Starting…" : "Run demo scan"}</Button>} />

      <Tabs value={tab} onValueChange={setTab} items={[{ value: "local", label: "Folder discovery" }, { value: "external", label: "External findings" }]} />

      {tab === "local" ? <div className=" grid gap-4 xl:grid-cols-[1.2fr_0.8fr]"><Card><CardHeader><CardTitle>Start a source-code scan</CardTitle><p className="mt-1 text-xs leading-5 text-muted-foreground">Source-code discovery is the currently supported scan mode. Quick and whole scans use approved workspace roots; specified scans require a folder.</p></CardHeader><CardContent><form onSubmit={reviewScan} className="space-y-5"><div className="grid gap-4 sm:grid-cols-2"><div className="space-y-2"><Label htmlFor="scan-type">Scan scope</Label><Select id="scan-type" value={scanType} onChange={(event) => setScanType(event.target.value as StartScanPayload["scan_type"])}><option value="specified">Specified folder</option><option value="quick">Quick scan</option><option value="whole">Whole workspace</option></Select></div><div className="space-y-2"><Label htmlFor="source-type">Discovery engine</Label><Input id="source-type" value="Source code" readOnly /></div></div><div className="space-y-2"><Label htmlFor="scan-target">Target folder</Label><div className="flex gap-2"><Input id="scan-target" value={target} onChange={(event) => setTarget(event.target.value)} placeholder="D:\\projects\\service" disabled={scanType !== "specified"} /><Button type="button" variant="outline" size="icon" onClick={() => setBrowseOpen(true)} disabled={scanType !== "specified"} aria-label="Browse folders"><FolderOpen className="h-4 w-4" aria-hidden="true" /></Button></div><p className="text-[11px] leading-4 text-muted-foreground">Browser mode uses the configured folder browser. Native folder selection is available in the desktop application.</p></div><div className="grid gap-4 sm:grid-cols-3"><div className="space-y-2"><Label htmlFor="max-files">Max files</Label><Input id="max-files" type="number" min="1" value={maxFiles} onChange={(event) => setMaxFiles(event.target.value)} /></div><div className="space-y-2"><Label htmlFor="max-depth">Max depth</Label><Input id="max-depth" type="number" min="1" value={maxDepth} onChange={(event) => setMaxDepth(event.target.value)} /></div><div className="space-y-2"><Label htmlFor="max-file-size">Max bytes</Label><Input id="max-file-size" type="number" min="1" value={maxFileSize} onChange={(event) => setMaxFileSize(event.target.value)} /></div></div>{previewRoots.length ? <div className="border bg-muted/20 p-3"><SectionLabel>Configured scan roots</SectionLabel><div className="mt-2 space-y-1">{previewRoots.map((root) => <div key={root.root} className="flex items-center justify-between gap-3 text-xs"><span className="truncate font-mono">{root.root}</span><span className="shrink-0 text-muted-foreground">{root.scan_all ? "Full tree" : "Selected"}</span></div>)}</div></div> : null}<div className="flex justify-end border-t pt-4"><Button type="submit" disabled={startScan.isPending}><ScanLine className="h-3.5 w-3.5" aria-hidden="true" />Review scan</Button></div></form></CardContent></Card><Card><CardHeader><CardTitle>Job monitor</CardTitle><p className="mt-1 text-xs leading-5 text-muted-foreground">Refreshes the selected job until a terminal state is reported.</p></CardHeader><CardContent>{currentJob ? <JobMonitor job={currentJob} isFetching={job.isFetching} onCancel={() => cancelScan.mutate(currentJob.id)} cancelling={cancelScan.isPending} /> : <EmptyState title="No active job" description="Start a scan or ingest external findings to see current progress here." />}</CardContent></Card></div> : <Card className=""><CardHeader><CardTitle>Ingest external discovery findings</CardTitle><p className="mt-1 text-xs leading-5 text-muted-foreground">Read a JSON file in the browser and submit its findings to the active workspace.</p></CardHeader><CardContent><div className="grid gap-5 lg:grid-cols-[0.8fr_1.2fr]"><div className="space-y-4"><div className="space-y-2"><Label htmlFor="external-file">Findings JSON</Label><label className="flex min-h-28 cursor-pointer flex-col items-center justify-center border border-dashed bg-muted/15 px-4 text-center hover:bg-muted/30"><Upload className="h-5 w-5 text-muted-foreground" aria-hidden="true" /><span className="mt-2 text-sm font-medium">{externalName || "Choose a JSON file"}</span><span className="mt-1 text-[11px] text-muted-foreground">The file is read locally in this browser.</span><input id="external-file" type="file" accept="application/json,.json" className="sr-only" onChange={readFile} /></label></div><div className="space-y-2"><Label htmlFor="external-target">Source label</Label><Input id="external-target" value={externalTarget} onChange={(event) => setExternalTarget(event.target.value)} placeholder="external-discovery-run" /></div><Button className="w-full" onClick={() => ingest.mutate()} disabled={ingest.isPending || !externalJson}><FileJson className="h-3.5 w-3.5" aria-hidden="true" />{ingest.isPending ? "Ingesting…" : "Validate and ingest"}</Button></div><div className="space-y-2"><Label htmlFor="external-json">Payload preview</Label><Textarea id="external-json" value={externalJson} onChange={(event) => setExternalJson(event.target.value)} placeholder={'{"source_type":"source_code","target":"discovery-source","findings":[…]}'} className="min-h-64 font-mono text-xs" /></div></div></CardContent></Card>}

      <Card><CardHeader className="flex-row items-center justify-between"><div><CardTitle>Scan history</CardTitle><p className="mt-1 text-xs text-muted-foreground">Newest jobs returned by the active scope.</p></div><RefreshButton onRefresh={() => scans.refetch()} aria-label="Refresh scan history" variant="ghost" /></CardHeader><CardContent className="p-0">{scans.isLoading ? <div className="p-5"><LoadingState label="Loading scan history" /></div> : scans.isError ? <div className="p-5"><ErrorState message={scans.error instanceof Error ? scans.error.message : undefined} onRetry={() => void scans.refetch()} /></div> : scanRows.length ? <Table><TableHeader><TableRow><TableHead>ID</TableHead><TableHead>Target</TableHead><TableHead>Status</TableHead><TableHead>Progress</TableHead><TableHead>Findings</TableHead><TableHead>Created</TableHead><TableHead /></TableRow></TableHeader><TableBody>{scanRows.map((scan) => <TableRow key={scan.id}><TableCell className="font-mono text-xs">#{scan.id}</TableCell><TableCell><p className="max-w-[280px] truncate font-medium">{scan.target || "—"}</p><p className="mt-0.5 text-[11px] text-muted-foreground">{titleCase(scan.source_type)}</p></TableCell><TableCell><StatusBadge status={scan.status} /></TableCell><TableCell><div className="flex min-w-28 items-center gap-2"><Progress value={scan.progress} className="w-20" /><span className="tnum text-[11px] text-muted-foreground">{scan.progress}%</span></div></TableCell><TableCell className="tnum">{formatNumber(scan.findings_count)}</TableCell><TableCell className="whitespace-nowrap text-xs text-muted-foreground">{formatDate(scan.created_at)}</TableCell><TableCell><Button variant="ghost" size="sm" onClick={() => setActiveJob(scan)}>View</Button></TableCell></TableRow>)}</TableBody></Table> : <div className="p-5"><EmptyState title="No scan history" description="No scan jobs are available in the active session." /></div>}</CardContent></Card>

      <Dialog open={reviewOpen} onOpenChange={setReviewOpen} title="Confirm local scan" description="The job will be associated with the active workspace after creation." footer={<><Button variant="ghost" onClick={() => setReviewOpen(false)}>Cancel</Button><Button onClick={confirmScan} disabled={startScan.isPending}>{startScan.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" /> : <ScanLine className="h-3.5 w-3.5" aria-hidden="true" />}Start scan</Button></>}><div className="space-y-3 text-sm"><div className="flex justify-between gap-4"><span className="text-muted-foreground">Scope</span><span className="font-medium">{titleCase(scanType)}</span></div><div className="flex justify-between gap-4"><span className="text-muted-foreground">Target</span><span className="max-w-[260px] truncate text-right font-mono text-xs">{target || "Configured roots"}</span></div><div className="border bg-warning/5 p-3 text-xs leading-5 text-warning"><div className="flex gap-2"><AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />Source-code scanning is the currently supported discovery mode. Review the target before starting a job.</div></div></div></Dialog>

      <Dialog open={browseOpen} onOpenChange={setBrowseOpen} title="Browse local folders" description="Folder names are provided by the configured workspace service. Directory contents are not uploaded." footer={<Button variant="outline" onClick={() => setBrowseOpen(false)}>Done</Button>}><div className="space-y-3"><div className="flex gap-2"><Input value={browsePath} onChange={(event) => setBrowsePath(event.target.value)} placeholder="C:\\ or /workspace" /><Button variant="outline" size="icon" onClick={() => setBrowsePath("")} aria-label="Show filesystem roots"><Folder className="h-4 w-4" aria-hidden="true" /></Button></div>{browse.isLoading ? <LoadingState label="Reading folders" /> : browse.isError ? <ErrorState message={browse.error instanceof Error ? browse.error.message : undefined} onRetry={() => void browse.refetch()} /> : browse.data?.error ? <p className="text-xs text-destructive">{browse.data.error}</p> : <div className="max-h-72 overflow-y-auto border">{browse.data?.folders?.length ? browse.data.folders.map((folder) => <button key={folder} type="button" className="flex w-full items-center gap-2 border-b px-3 py-2.5 text-left text-sm last:border-0 hover:bg-secondary" onClick={() => { const next = joinPath(browse.data?.path || browsePath, folder); setBrowsePath(next); setTarget(next); }}><Folder className="h-4 w-4 text-primary" aria-hidden="true" /><span className="truncate">{folder}</span></button>) : <p className="p-4 text-xs text-muted-foreground">No subfolders returned.</p>}</div>}</div></Dialog>
    </div>
  );
}

function JobMonitor({ job, isFetching, onCancel, cancelling }: { job: ScanJob; isFetching: boolean; onCancel: () => void; cancelling: boolean }) {
  const active = !isTerminalStatus(job.status);
  return <div className="space-y-4"><div className="flex items-start justify-between gap-3"><div><p className="font-mono text-xs text-muted-foreground">JOB #{job.id}</p><p className="mt-1 max-w-[240px] truncate text-sm font-medium" title={job.target}>{job.target || "Configured scan roots"}</p></div><StatusBadge status={job.status} /></div><Progress value={job.progress} /><div className="flex items-center justify-between text-xs"><span className="text-muted-foreground">{isFetching ? "Refreshing state…" : "Current progress"}</span><span className="tnum font-medium">{job.progress}%</span></div><div className="grid grid-cols-2 gap-3 border-t pt-4 text-xs"><div><p className="text-muted-foreground">Findings</p><p className="tnum mt-1 font-medium">{formatNumber(job.findings_count)}</p></div><div><p className="text-muted-foreground">Created</p><p className="mt-1">{formatDate(job.created_at)}</p></div></div>{job.error ? <div className="flex gap-2 border border-destructive/30 bg-destructive/5 p-3 text-xs leading-5 text-destructive"><XCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />{job.error}</div> : null}{active ? <Button variant="outline" className="w-full" onClick={onCancel} disabled={cancelling}>{cancelling ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" /> : <XCircle className="h-3.5 w-3.5" aria-hidden="true" />}{cancelling ? "Cancelling…" : "Cancel scan"}</Button> : <div className="flex items-center gap-2 border border-success/30 bg-success/5 p-3 text-xs text-success"><CheckCircle2 className="h-4 w-4" aria-hidden="true" />Terminal state received.</div>}</div>;
}
