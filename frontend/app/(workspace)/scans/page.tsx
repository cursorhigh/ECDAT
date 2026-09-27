"use client";

import { ChangeEvent, FormEvent, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, BadgeCheck, Boxes, Check, CheckCircle2, FileCode2, FileJson, FileType, Folder, FolderOpen, Loader2, Package, Play, Radar, ScanLine, Search, ShieldCheck, Upload, XCircle } from "lucide-react";
import { Badge, type BadgeProps } from "@/components/ui/badge";
import { Tooltip } from "@/components/ui/tooltip";
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
import { GraphPanel } from "@/components/data/graph-panel";
import { useToast } from "@/components/feedback/toast";
import { api, isNoScanSelected } from "@/lib/api/client";
import type { Handoff, NormalizedFinding, ScanBatch, ScanJob, ScanPreview, ScannerDescriptor, ScannerRegistry, StartScanPayload } from "@/lib/api/types";
import { useSession } from "@/lib/session-context";
import { cn, formatDate, formatNumber, titleCase, truncate } from "@/lib/utils";

const BATCH_ACTIVE = new Set(["queued", "validating", "running", "cancelling"]);

/**
 * Icon per discovery source for the compact source picker. Falling back to
 * ScanLine means a newly registered source still renders a recognisable tile
 * instead of an empty box.
 */
const SOURCE_ICONS: Record<string, typeof ScanLine> = {
  source_code: FileCode2,
  binary: FileType,
  certificate: BadgeCheck,
  container: Package,
  dependency: Boxes,
};

/** Findings per page. Must match the backend page size for `findingPages`. */
const FINDINGS_PAGE_SIZE = 25;

/** One option a selected source exposes, plus which sources honour it. */type LimitField = {
  label: string;
  type?: string;
  default?: string | number;
  min?: number;
  help?: string;
  applies_to?: string[];
};

const TERMINAL_STATUSES = new Set(["completed", "complete", "failed", "cancelled", "canceled", "partial"]);
const CANCELLABLE_STATUSES = new Set(["queued", "running"]);

const STAGE_LABELS: Record<string, string> = {
  enumerating: "Enumerating items",
  inspecting: "Inspecting items",
  persisting: "Recording findings",
  normalizing: "Normalizing findings",
  correlating: "Linking related artefacts",
  done: "Finished",
  cancelling: "Stopping",
  cancelled: "Stopped",
  failed: "Failed"
};

// `quick` walks the operating system's standard key and certificate
// locations (~/.ssh, /etc/ssl, ~/.gnupg and so on) — it is not a workspace
// connection, which is configured once under Settings.
const scanScopeOptions: Array<{ value: StartScanPayload["scan_type"]; label: string; hint: string }> = [
  { value: "specified", label: "Selected target", hint: "Only the path you choose." },
  { value: "quick", label: "Standard key locations", hint: "The usual places certificates, keys and crypto config live on this system." },
  { value: "whole", label: "Entire environment", hint: "Every drive or filesystem on this machine. Slowest, and reads far more than you probably need." },
];

function joinPath(parent: string, child: string) {
  if (!parent) return child;
  return `${parent.replace(/[\\/]+$/, "")}\\${child}`;
}

function isDemoJob(job: ScanJob) {
  return String(job.target || "").toLowerCase().startsWith("demo:");
}

function confidenceLevel(value?: number | null): { label: string; variant: BadgeProps["variant"] } {
  const score = Number(value);
  if (!Number.isFinite(score) || score <= 0) return { label: "Unknown", variant: "muted" };
  if (score >= 0.85) return { label: "High", variant: "success" };
  if (score >= 0.6) return { label: "Medium", variant: "warning" };
  return { label: "Low", variant: "danger" };
}

function jobOutcome(status?: string | null) {
  const key = String(status || "").toLowerCase();
  if (key === "completed" || key === "complete") {
    return { variant: "success" as const, title: "Discovery completed", detail: "All configured sources reported a terminal result." };
  }
  if (key === "failed") {
    return { variant: "danger" as const, title: "Discovery failed", detail: "This job did not complete. Review the reported reason before retrying." };
  }
  if (key === "cancelled") {
    return { variant: "muted" as const, title: "Discovery cancelled", detail: "This job was stopped before it finished." };
  }
  if (key === "partial") {
    return { variant: "warning" as const, title: "Partial discovery", detail: "This job finished with incomplete coverage. The list below records exactly what could not be inspected." };
  }
  return null;
}

export default function ScansPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { ready, scopeKey, adoptSession , hasSession } = useSession();
  const { pushToast } = useToast();
  const queryClient = useQueryClient();

  const [tab, setTab] = useState("scan");
  const [sourceType, setSourceType] = useState("");
  // Which discovery sources to run. Empty means "all of them" — the default,
  // because a user asking to discover something wants everything applicable.
  const [chosenSources, setChosenSources] = useState<string[]>([]);
  const [sourcesTouched, setSourcesTouched] = useState(false);
  // A multi-source run being followed, when the latest action produced one.
  const [activeBatchId, setActiveBatchId] = useState<number | null>(null);
  // Importing is an occasional task, so its whole form stays hidden until asked
  // for rather than sitting under the scan form on every visit.
  const [showImport, setShowImport] = useState(false);
  const [scanType, setScanType] = useState<StartScanPayload["scan_type"]>("specified");
  const [target, setTarget] = useState("");
  const [limits, setLimits] = useState<Record<string, string>>({});
  const [browseOpen, setBrowseOpen] = useState(false);
  const [browsePath, setBrowsePath] = useState("");
  const [reviewOpen, setReviewOpen] = useState(false);
  const [externalName, setExternalName] = useState("");
  const [externalTarget, setExternalTarget] = useState("");
  const [externalJson, setExternalJson] = useState("");
  const [cryptoOnly, setCryptoOnly] = useState(true);
  const [kindFilter, setKindFilter] = useState("");

  const scans = useQuery({ queryKey: ["scans", scopeKey], queryFn: () => api.scans({ page: 1 }), enabled: ready && hasSession });
  const registry = useQuery({ queryKey: ["scanners"], queryFn: () => api.scanners(), enabled: ready, staleTime: 300_000 });
  const preview = useQuery({ queryKey: ["scan-preview", scanType, scopeKey], queryFn: () => api.scanPreview(scanType), enabled: ready && scanType !== "specified" });
  const browse = useQuery({ queryKey: ["browse", browsePath, scopeKey], queryFn: () => api.browse(browsePath || undefined), enabled: ready && browseOpen });

  const availableScanners = (registry.data?.scanners || []).filter((scanner) => scanner.status === "available");

  // Effective selection: whatever the user ticked, or every available source.
  const activeSources = sourcesTouched
    ? chosenSources
    : availableScanners.map((scanner) => scanner.source_type);

  // A source that cannot read the chosen target is excluded by the backend
  // too, but hiding it here means the user is not offered a choice that will
  // be refused.
  const targetIsFile = Boolean(target) && /\.tar(\.gz)?$|\.tgz$/i.test(target);
  const eligibleSources = availableScanners.filter((scanner) => {
    if (!targetIsFile) return true;
    return scanner.supported_targets?.includes("file");
  });
  const ineligibleSources = availableScanners.filter(
    (scanner) => !eligibleSources.includes(scanner),
  );

  const toggleSource = (value: string) => {
    setSourcesTouched(true);
    setChosenSources((previous) => {
      const base = sourcesTouched ? previous : availableScanners.map((s) => s.source_type);
      return base.includes(value) ? base.filter((item) => item !== value) : [...base, value];
    });
  };

  const setAllSources = (all: boolean) => {
    setSourcesTouched(true);
    setChosenSources(all ? eligibleSources.map((scanner) => scanner.source_type) : []);
  };

  // Options are per-source. With several sources selected, show the union and
  // label it, so a field never appears for a source that cannot honour it.
  const limitFields = Array.from(
    new Map<string, LimitField>(
      eligibleSources
        .filter((scanner) => activeSources.includes(scanner.source_type))
        .flatMap((scanner) => Object.entries(scanner.configuration_schema || {}))
        .map(([key, field]) => [
          key,
          {
            ...(field as LimitField),
            applies_to: eligibleSources
              .filter((s) => s.configuration_schema && key in s.configuration_schema)
              .map((s) => s.name),
          },
        ]),
    ).entries(),
  );

  // True when any selected source inspects files without running them. Renders
  // from declared capabilities so it cannot drift from actual behaviour.
  const noExecutionSelected = availableScanners.some(
    (scanner) =>
      activeSources.includes(scanner.source_type) &&
      scanner.capabilities?.includes("no_execution"),
  );

  const requestedScanId = Number(searchParams.get("scan")) || null;
  const [selection, setSelection] = useState<{ scopeKey: string; jobId: number | null; findingsPage: number }>({
    scopeKey,
    jobId: requestedScanId,
    findingsPage: 1
  });

  if (selection.scopeKey !== scopeKey) {
    setSelection({ scopeKey, jobId: requestedScanId, findingsPage: 1 });
  }

  const selectedJobId = selection.jobId;
  const findingsPage = selection.findingsPage;

  const job = useQuery({
    queryKey: ["scan-job", selectedJobId, scopeKey],
    queryFn: () => api.scan(selectedJobId!),
    enabled: Boolean(selectedJobId),
    refetchInterval: (query) => (TERMINAL_STATUSES.has(String(query.state.data?.status || "").toLowerCase()) ? false : 3000)
  });

  const findings = useQuery({
    queryKey: ["normalized-findings", scopeKey, findingsPage, kindFilter],
    queryFn: () => api.normalizedFindings({ page: findingsPage, ...(kindFilter ? { kind: kindFilter } : {}) }),
    enabled: ready && hasSession && tab === "findings"
  });

  // Artefact-kind facets: how the findings split into certificates, keys,
  // libraries, protocols and so on, with counts.
  const kindFacetsQuery = useQuery({
    queryKey: ["normalized-kinds", scopeKey],
    queryFn: api.normalizedKindCounts,
    enabled: ready && hasSession
  });
  const kindFacets = kindFacetsQuery.data?.kinds || [];
  const kindTotal = kindFacetsQuery.data?.total || 0;

  // The Discover -> Understand contract, as a verdict rather than a table. It
  // used to be a whole tab that repeated the counts, coverage and findings shown
  // here and on the job panel; only the verdict was unique, so only it stayed.
  const contractSummary = useQuery({
    queryKey: ["handoff-summary", scopeKey],
    queryFn: () => api.handoff({ summary: 1 }),
    enabled: ready && hasSession && tab === "findings"
  });

  const dependencies = useQuery({
    queryKey: ["dependencies", scopeKey, cryptoOnly],
    queryFn: () => api.dependencies(cryptoOnly ? { crypto_only: 1 } : undefined),
    enabled: ready && hasSession && tab === "dependencies"
  });

  const depGraph = useQuery({
    queryKey: ["dependency-graph", scopeKey],
    queryFn: () => api.dependencyGraph(),
    enabled: ready && hasSession && tab === "dependencies"
  });

  const selectJob = (id: number | null) => {
    setSelection({ scopeKey, jobId: id, findingsPage: 1 });
    router.replace(id ? `/scans?scan=${id}` : "/scans", { scroll: false });
  };

  const goToFindingsPage = (page: number) => {
    setSelection((previous) => ({ ...previous, findingsPage: Math.max(1, page) }));
  };

  // Changing kind must return to page 1, or a deep page can land empty.
  const selectKind = (kind: string) => {
    setKindFilter(kind);
    setSelection((previous) => ({ ...previous, findingsPage: 1 }));
  };

  // A multi-source run is followed as one unit; each source reports its own
  // progress underneath. Polling stops once every source is terminal.
  const batchLive = useQuery({
    queryKey: ["scan-batch", scopeKey, activeBatchId],
    queryFn: () => api.scanBatch(activeBatchId!),
    enabled: ready && hasSession && activeBatchId !== null,
    refetchInterval: (query) =>
      BATCH_ACTIVE.has(String(query.state.data?.status || "").toLowerCase()) ? 1500 : false,
  });
  const activeBatch = batchLive.data ?? null;

  const cancelBatch = useMutation({
    mutationFn: (id: number) => api.cancelScanBatch(id),
    onSuccess: async () => {
      pushToast("Cancellation requested for every source.", "info");
      await queryClient.invalidateQueries({ queryKey: ["scan-batch"] });
    },
    onError: (error) =>
      pushToast(error instanceof Error ? error.message : "Cancellation failed.", "error"),
  });

  const startScan = useMutation({
    mutationFn: async (payload: StartScanPayload) => api.startScan(payload),
    onSuccess: async (created) => {
      if (created.session) await adoptSession(created.session.id, created.session.name);
      // A multi-source run is a batch, not a job: it has no single job id to
      // follow, so it gets its own monitor and its own query.
      if (Array.isArray(created.sources) && created.sources.length) {
        const batch = created as unknown as ScanBatch;
        setActiveBatchId(batch.id);
        setTab("scan");
        setReviewOpen(false);
        const skipped = batch.excluded?.length || 0;
        pushToast(
          `Discovery started across ${batch.sources.length} source${batch.sources.length === 1 ? "" : "s"}${skipped ? `, ${skipped} skipped` : ""}.`,
          skipped ? "info" : "success",
        );
      } else {
        setActiveBatchId(null);
        selectJob(created.id);
        setTab("scan");
        setReviewOpen(false);
        pushToast(`Discovery job #${created.id} started.`, "success");
      }
      await queryClient.invalidateQueries({ queryKey: ["scans"] });
      await queryClient.invalidateQueries({ queryKey: ["scan-batch"] });
    },
    onError: (error) => pushToast(error instanceof Error ? error.message : "Discovery could not be started.", "error")
  });

  const demoScan = useMutation({
    mutationFn: api.demoScan,
    onSuccess: async (created) => {
      selectJob(created.id);
      setTab("scan");
      pushToast(`Demo discovery job #${created.id} is processing.`, "success");
      await queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
    onError: (error) => pushToast(error instanceof Error ? error.message : "Demo discovery could not be started.", "error")
  });

  const cancelScan = useMutation({
    mutationFn: (id: number) => api.cancelScan(id),
    onSuccess: async () => {
      pushToast("Cancellation requested.", "info");
      await queryClient.invalidateQueries({ queryKey: ["scans"] });
      if (selectedJobId) await queryClient.invalidateQueries({ queryKey: ["scan-job", selectedJobId] });
    },
    onError: (error) => pushToast(error instanceof Error ? error.message : "Discovery could not be cancelled.", "error")
  });

  const ingest = useMutation({
    mutationFn: async () => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(externalJson);
      } catch {
        throw new Error("The selected file is not valid JSON.");
      }
      const payload = Array.isArray(parsed)
        ? { source_type: "source_code", target: externalTarget || externalName || "imported-findings", findings: parsed }
        : parsed;
      if (!payload || typeof payload !== "object" || !Array.isArray((payload as { findings?: unknown }).findings)) {
        throw new Error("The payload must contain a findings array.");
      }
      return api.ingestScanData(payload as Record<string, unknown>);
    },
    onSuccess: async (created) => {
      if (created.session) await adoptSession(created.session.id, created.session.name);
      selectJob(created.id);
      setTab("scan");
      pushToast(`Imported findings recorded under job #${created.id}.`, "success");
      await queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
    onError: (error) => pushToast(error instanceof Error ? error.message : "Findings could not be imported.", "error")
  });

  const reviewScan = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (scanType === "specified" && !target.trim()) {
      pushToast("Enter a discovery target before continuing.", "error");
      return;
    }
    if (!activeSources.length) {
      pushToast("Select at least one discovery source.", "error");
      return;
    }
    setReviewOpen(true);
  };

  const confirmScan = () => {
    if (!activeSources.length) {
      pushToast("Select at least one discovery source.", "error");
      return;
    }
    const options: Record<string, number> = {};
    for (const [key, field] of limitFields) {
      const raw = limits[key];
      const parsed = raw === undefined ? Number(field.default) : Number(raw);
      if (Number.isFinite(parsed) && parsed > 0) options[key] = parsed;
    }

    startScan.mutate({
      scan_type: scanType,
      // One request for every chosen source; the backend fans it out and
      // returns a single run to follow.
      source_types: activeSources,
      source_type: activeSources[0],
      target: target.trim(),
      options
    });
  };

  const readFile = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    setExternalName(file.name);
    const reader = new FileReader();
    reader.onload = () => setExternalJson(String(reader.result || ""));
    reader.onerror = () => pushToast("The selected file could not be read.", "error");
    reader.readAsText(file);
  };

  const scanRows = scans.data?.results || [];
  const findingRows = findings.data?.results || [];
  const findingTotal = findings.data?.count || 0;
  const findingPages = Math.max(1, Math.ceil(findingTotal / FINDINGS_PAGE_SIZE));
  // Row numbers continue across pages, so "#37" means the same finding whether
  // it is reached from page 1 or page 2.
  const findingRowOffset = (findingsPage - 1) * FINDINGS_PAGE_SIZE;
  const dependencyRows = dependencies.data?.results || [];
  const dependencyTotal = dependencies.data?.count || 0;
  const keyServices = Array.from(
    new Set(dependencyRows.map((row) => row.key_service).filter((service): service is string => Boolean(service)))
  );
  // Reverse index so each package can show what pulls it in and what it backs.
  const dependentsByNode = new Map<string, number>();
  const providesByNode = new Map<string, number>();
  for (const edge of depGraph.data?.dependency_edges || []) {
    if (edge.kind === "depends_on") {
      dependentsByNode.set(edge.to, (dependentsByNode.get(edge.to) || 0) + 1);
    } else if (edge.kind === "provides") {
      providesByNode.set(edge.from, (providesByNode.get(edge.from) || 0) + 1);
    }
  }
  const nodeIdByPackage = new Map<string, string>();
  for (const node of depGraph.data?.dependency_nodes || []) {
    nodeIdByPackage.set(`${node.ecosystem}:${node.package}`, node.id);
  }
  const transitiveCount = (depGraph.data?.dependency_edges || []).filter((edge) => edge.kind === "depends_on").length;
  const providesCount = providesByNode.size;

  const jobPanel = !selectedJobId ? (
      <EmptyState title="No job selected" description="Start a discovery scan below, or open a previous scan from the audit history to follow its current state." />
  ) : job.isLoading ? (
    <LoadingState label="Loading job state" />
  ) : job.isError && !isNoScanSelected(job.error) ? (
    <ErrorState
      message={job.error instanceof Error ? job.error.message : "This job is not part of the selected scan."}
      onRetry={() => void job.refetch()}
    />
  ) : job.data ? (
    <JobMonitor
      job={job.data}
      isFetching={job.isFetching}
      onCancel={() => cancelScan.mutate(job.data!.id)}
      cancelling={cancelScan.isPending}
    />
  ) : null;

  // A multi-source run takes precedence: it is the more recent action.
  const batchPanel = activeBatchId !== null && activeBatch ? (
    <BatchMonitor
      batch={activeBatch}
      scanners={availableScanners}
      onCancel={() => cancelBatch.mutate(activeBatch.id)}
      cancelling={cancelBatch.isPending}
    />
  ) : activeBatchId !== null ? (
    <LoadingState label="Loading multi-source run" />
  ) : null;

  return (
    <div className="space-y-6">
      <PageHeader
        compact
        eyebrow="Discover"
        title="Cryptographic discovery"
        description="Collect evidence-backed cryptographic observations across connected sources. Classification, risk, and migration reasoning are produced by later stages."
        actions={
          <Button variant="outline" size="sm" onClick={() => demoScan.mutate()} disabled={demoScan.isPending}>
            <Play className="h-3.5 w-3.5" aria-hidden="true" />
            {demoScan.isPending ? "Starting…" : "Run demo discovery"}
          </Button>
        }
      />

      <Tabs
        value={tab}
        onValueChange={setTab}
        items={[
          { value: "scan", label: "Scan" },
          { value: "findings", label: "Findings" },
          { value: "graph", label: "Graph" },
          { value: "dependencies", label: "Dependencies", count: dependencyTotal || undefined }
        ]}
      />

      {!hasSession && tab !== "scan" ? (
        <Card>
          <CardContent className="p-0">
            <EmptyState
              title="No scan selected"
              description="Each scan keeps its own findings, graph and dependencies. Open one from the audit history, or start a new scan."
              action={
                <Button type="button" variant="secondary" size="sm" onClick={() => setTab("scan")}>
                  Start a scan
                </Button>
              }
            />
          </CardContent>
        </Card>
      ) : null}


      {tab === "scan" ? (
        <div className="grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
          <Card>
            <CardHeader>
              <CardTitle>Start a discovery scan</CardTitle>
              <p className="mt-1 text-xs leading-5 text-muted-foreground">
                Discovery records what exists and where it was observed. It does not assign risk, priority, or replacement guidance.
              </p>
            </CardHeader>
            <CardContent>
              <form onSubmit={reviewScan} className="space-y-5">
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="scan-type">Discovery scope</Label>
                    <Select id="scan-type" value={scanType} onChange={(event) => setScanType(event.target.value as StartScanPayload["scan_type"])}>
                      {scanScopeOptions.map((option) => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </Select>
                    <p className="text-[11px] leading-4 text-muted-foreground">
                      {scanScopeOptions.find((option) => option.value === scanType)?.hint}
                    </p>
                  </div>
                  <fieldset className="space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <legend className="text-sm font-medium leading-none">Discovery sources</legend>
                      {eligibleSources.length > 1 ? (
                        <div className="flex gap-2">
                          <button
                            type="button"
                            onClick={() => setAllSources(true)}
                            className="text-[11px] text-primary hover:underline"
                          >
                            Select all
                          </button>
                          <span className="text-[11px] text-muted-foreground" aria-hidden="true">/</span>
                          <button
                            type="button"
                            onClick={() => setAllSources(false)}
                            className="text-[11px] text-primary hover:underline"
                          >
                            Clear
                          </button>
                        </div>
                      ) : null}
                    </div>

                    <div className="flex flex-wrap gap-2" role="group" aria-label="Discovery sources">
                      {eligibleSources.map((scanner) => {
                        const checked = activeSources.includes(scanner.source_type);
                        const Icon = SOURCE_ICONS[scanner.source_type] || ScanLine;
                        return (
                          <Tooltip
                            key={scanner.id}
                            placement="top"
                            offset={8}
                            msg={
                              <span className="block">
                                <span className="block font-semibold text-foreground">{scanner.name}</span>
                                <span className="mt-0.5 block">{scanner.description}</span>
                              </span>
                            }
                          >
                            <button
                              type="button"
                              role="checkbox"
                              aria-checked={checked}
                              aria-label={`${scanner.name}${checked ? " (selected)" : ""}`}
                              onClick={() => toggleSource(scanner.source_type)}
                              className={cn(
                                "group relative flex h-12 w-12 items-center justify-center border transition-colors",
                                checked
                                  ? "border-primary bg-primary/10 text-primary"
                                  : "border-border text-muted-foreground hover:border-primary/40 hover:bg-muted/50 hover:text-foreground",
                              )}
                            >
                              <Icon className="h-5 w-5" aria-hidden="true" />
                              {checked ? (
                                <span
                                  className="absolute -right-1 -top-1 flex h-3.5 w-3.5 items-center justify-center bg-primary text-[9px] font-bold text-primary-foreground"
                                  aria-hidden="true"
                                >
                                  <Check className="h-2.5 w-2.5" />
                                </span>
                              ) : null}
                            </button>
                          </Tooltip>
                        );
                      })}
                    </div>

                    {ineligibleSources.length ? (
                      <>
                        <div className="flex flex-wrap gap-2" aria-label="Sources unavailable for this target">
                          {ineligibleSources.map((scanner) => {
                            const Icon = SOURCE_ICONS[scanner.source_type] || ScanLine;
                            return (
                              <Tooltip
                                key={scanner.id}
                                placement="top"
                                offset={8}
                                msg={
                                  <span className="block">
                                    <span className="block font-semibold text-foreground">{scanner.name}</span>
                                    <span className="mt-0.5 block">
                                      Not available for a file target. Select a folder to include it.
                                    </span>
                                  </span>
                                }
                              >
                                <span
                                  tabIndex={0}
                                  aria-label={`${scanner.name} (unavailable for a file target)`}
                                  className="flex h-12 w-12 cursor-not-allowed items-center justify-center border border-dashed border-border text-muted-foreground/50"
                                >
                                  <Icon className="h-5 w-5" aria-hidden="true" />
                                </span>
                              </Tooltip>
                            );
                          })}
                        </div>
                        <p className="text-[11px] leading-4 text-muted-foreground">
                          Dashed sources need a folder target. Choose a folder to include them.
                        </p>
                      </>
                    ) : null}

                    {!activeSources.length ? (
                      <p className="text-[11px] text-destructive">
                        Select at least one discovery source.
                      </p>
                    ) : (
                      <p className="text-[11px] leading-4 text-muted-foreground">
                        {activeSources.length === availableScanners.length
                          ? `All ${availableScanners.length} sources will run against the same target. Each reports its own progress and coverage.`
                          : `${activeSources.length} of ${availableScanners.length} sources selected. Each reports its own progress and coverage.`}
                      </p>
                    )}
                  </fieldset>
                </div>

                {noExecutionSelected ? (
                  <div className="flex gap-2 border border-info/30 bg-info/5 p-3 text-[11px] leading-4 text-info">
                    <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                    <span>Artefacts are read as bytes only. Nothing in the target is loaded, unpacked, or executed.</span>
                  </div>
                ) : null}

                {scanType === "specified" ? (
                  <div className="space-y-2">
                    <Label htmlFor="scan-target">Discovery target</Label>
                    <div className="flex gap-2">
                      <Input
                        id="scan-target"
                        value={target}
                        onChange={(event) => setTarget(event.target.value)}
                        placeholder="C:\\path\\to\\folder"
                      />
                      <Button type="button" variant="outline" size="icon" onClick={() => setBrowseOpen(true)} aria-label="Browse folders">
                        <FolderOpen className="h-4 w-4" aria-hidden="true" />
                      </Button>
                    </div>
                    <p className="text-[11px] leading-4 text-muted-foreground">
                      Every selected source reads this one location, including files without an
                      extension.
                    </p>
                  </div>
                ) : (
                  <ScopeCoverage scope={scanType} registry={registry.data} preview={preview.data} />
                )}

                {limitFields.length ? (
                  <div className={`grid gap-4 ${limitFields.length >= 3 ? "sm:grid-cols-3" : "sm:grid-cols-2"}`}>
                    {limitFields.map(([key, field]) => (
                      <div key={key} className="space-y-2">
                        <Label htmlFor={`limit-${key}`}>{field.label}</Label>
                        <Input
                          id={`limit-${key}`}
                          type="number"
                          min={field.min ?? 1}
                          value={limits[key] ?? String(field.default)}
                          onChange={(event) => setLimits((previous) => ({ ...previous, [key]: event.target.value }))}
                        />
                      </div>
                    ))}
                  </div>
                ) : null}

                <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-4">
                  <p className="max-w-sm text-[11px] leading-4 text-muted-foreground">
                    Discovery inspects the entire target with no depth or size ceiling. It is read-only and never modifies discovered material.
                  </p>
                  <Button type="submit" disabled={startScan.isPending}>
                    <ScanLine className="h-3.5 w-3.5" aria-hidden="true" />
                    Review discovery
                  </Button>
                </div>
              </form>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex-row items-start justify-between">
              <div>
                <CardTitle>Discovery activity</CardTitle>
                <p className="mt-1 text-xs leading-5 text-muted-foreground">Current state of the selected job.</p>
              </div>
              <Radar className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
            </CardHeader>
            <CardContent>
              {batchPanel || jobPanel}
              {selectedJobId ? (
                <Button variant="ghost" size="sm" className="mt-3 w-full" onClick={() => selectJob(null)}>
                  Clear selection
                </Button>
              ) : null}
            </CardContent>
          </Card>
        </div>
      ) : null}

      {tab === "scan" ? (
        <div>
          <button
            type="button"
            onClick={() => setShowImport((previous) => !previous)}
            aria-expanded={showImport}
            className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"
          >
            <FileJson className="h-3.5 w-3.5" aria-hidden="true" />
            {showImport ? "Hide import" : "Import findings recorded by another tool"}
          </button>
          <p className="mt-1 text-[11px] leading-4 text-muted-foreground">
            Creates its own scan, so imported findings stay separate from a discovery run.
          </p>
        </div>
      ) : null}

      {tab === "scan" && showImport ? (
        <Card>
          <CardHeader>
            <CardTitle>Import discovery findings</CardTitle>
            <p className="mt-1 text-xs leading-5 text-muted-foreground">
              Bring in findings another tool already recorded, as JSON. They become their own scan
              with their own findings, graph and dependencies.
            </p>
          </CardHeader>
          <CardContent>
            <div className="grid gap-5 lg:grid-cols-[0.8fr_1.2fr]">
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="external-file">Findings file</Label>
                  <Input id="external-file" type="file" accept=".json,application/json" onChange={readFile} />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="external-target">Scan label</Label>
                  <Input
                    id="external-target"
                    value={externalTarget}
                    onChange={(event) => setExternalTarget(event.target.value)}
                    placeholder="imported-findings"
                  />
                </div>
                <Button
                  onClick={() => ingest.mutate()}
                  disabled={ingest.isPending || !externalJson.trim()}
                  className="w-full"
                >
                  {ingest.isPending ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                  ) : (
                    <Upload className="h-3.5 w-3.5" aria-hidden="true" />
                  )}
                  Import findings
                </Button>
                {ingest.isError ? (
                  <p className="text-xs text-destructive">
                    {ingest.error instanceof Error ? ingest.error.message : "The import was rejected."}
                  </p>
                ) : null}
              </div>
              <div className="space-y-2">
                <Label htmlFor="external-json">Payload preview</Label>
                <Textarea
                  id="external-json"
                  value={externalJson}
                  onChange={(event) => setExternalJson(event.target.value)}
                  placeholder={'{"source_type":"source_code","target":"discovery-source","findings":[…]}'}
                  className="min-h-64 font-mono text-xs"
                />
              </div>
            </div>
          </CardContent>
        </Card>
      ) : null}

      {tab === "findings" && hasSession ? (
        <Card>
          <CardHeader className="flex-row items-start justify-between">
            <div>
              <CardTitle>Discovered findings</CardTitle>
              <p className="mt-1 text-xs leading-5 text-muted-foreground">
                What discovery actually observed, grouped by what kind of artefact it is. Every finding carries a confidence level; nothing here is a risk verdict.
              </p>
              <ContractStatus summary={contractSummary.data} />
            </div>
            <div className="flex items-center gap-2">
              {/* Nothing to search, filter or refresh until something exists. */}
              {kindTotal > 0 ? (
                <>
                  <Search className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
                  <RefreshButton onRefresh={() => findings.refetch()} aria-label="Refresh findings" variant="ghost" />
                </>
              ) : null}
            </div>
          </CardHeader>

          {kindFacets.length > 1 ? (
            <div className="flex flex-wrap items-center gap-2 border-b px-5 py-3">
              <span className="text-[11px] font-semibold uppercase tracking-[0.1em] text-muted-foreground">
                Kind
              </span>
              <button
                type="button"
                onClick={() => selectKind("")}
                aria-pressed={kindFilter === ""}
                className={`border px-2.5 py-1 text-[11px] transition-colors ${
                  kindFilter === ""
                    ? "border-primary bg-primary/10 text-primary"
                    : "border-border text-muted-foreground hover:bg-muted"
                }`}
              >
                All {formatNumber(kindTotal)}
              </button>
              {kindFacets.map((facet) => (
                <button
                  key={facet.kind}
                  type="button"
                  onClick={() => selectKind(facet.kind)}
                  aria-pressed={kindFilter === facet.kind}
                  className={`border px-2.5 py-1 text-[11px] transition-colors ${
                    kindFilter === facet.kind
                      ? "border-primary bg-primary/10 text-primary"
                      : "border-border text-muted-foreground hover:bg-muted"
                  }`}
                >
                  {facet.label} <span className="tnum">{formatNumber(facet.count)}</span>
                </button>
              ))}
            </div>
          ) : null}
          <CardContent className="px-1">
            {findings.isLoading ? (
              <div className="p-4">
                <LoadingState label="Loading discovered findings" />
              </div>
            ) : findings.isError && !isNoScanSelected(findings.error) ? (
              <div className="p-4">
                <ErrorState message={findings.error instanceof Error ? findings.error.message : undefined} onRetry={() => void findings.refetch()} />
              </div>
            ) : findingRows.length ? (
              <>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-12 text-right">#</TableHead>
                      <TableHead>Artefact</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Key size</TableHead>
                      <TableHead>Protocol</TableHead>
                      <TableHead>Library</TableHead>
                      <TableHead>Evidence</TableHead>
                      <TableHead className="text-right">Confidence</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {findingRows.map((finding: NormalizedFinding, rowIndex) => (
                      <TableRow key={finding.id}>
                        <TableCell className="tnum whitespace-nowrap pr-1 text-right font-mono text-[11px] text-muted-foreground">
                          #{formatNumber(findingRowOffset + rowIndex + 1)}
                        </TableCell>
                        <TableCell className="min-w-0">
                          <p className="truncate font-medium">{finding.algorithm || finding.family_display || titleCase(finding.family)}</p>
                          <p className="mt-0.5 text-[11px] text-muted-foreground">
                            {finding.curve ? `${finding.curve} · ` : ""}
                            {finding.family_display || titleCase(finding.family)}
                          </p>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className="normal-case tracking-normal">
                            {finding.kind_display || titleCase(finding.kind)}
                          </Badge>
                        </TableCell>
                        <TableCell className="tnum text-xs">{finding.key_size ? `${formatNumber(finding.key_size)} bits` : "—"}</TableCell>
                        <TableCell className="text-xs">{finding.protocol || "—"}</TableCell>
                        <TableCell className="text-xs">
                          {finding.library ? (
                            <>
                              <span className="font-mono">{finding.library}</span>
                              {finding.library_version ? <span className="ml-1 text-muted-foreground">{finding.library_version}</span> : null}
                            </>
                          ) : (
                            "—"
                          )}
                        </TableCell>
                        <TableCell className="max-w-[260px]">
                          <EvidenceCell finding={finding} />
                        </TableCell>
                        <TableCell className="text-right">
                          <ConfidenceBadge value={finding.confidence} />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                <div className="flex flex-wrap items-center justify-between gap-3 border-t px-5 py-3 text-xs text-muted-foreground">
                  <span className="tnum">
                    {formatNumber(findingTotal)} finding{findingTotal === 1 ? "" : "s"}
                    {findingPages > 1 ? ` · page ${findingsPage} of ${findingPages}` : ""}
                  </span>
                  {/* Paging controls only exist once there is more than one page. */}
                  {findingPages > 1 ? (
                    <div className="flex gap-2">
                      <Button variant="outline" size="sm" disabled={findingsPage <= 1 || findings.isFetching} onClick={() => goToFindingsPage(findingsPage - 1)}>
                        Previous
                      </Button>
                      <Button variant="outline" size="sm" disabled={findingsPage >= findingPages || findings.isFetching} onClick={() => goToFindingsPage(findingsPage + 1)}>
                        Next
                      </Button>
                    </div>
                  ) : null}
                </div>
              </>
            ) : (
              <div className="p-4">
                <EmptyState
                  title={kindFilter ? "No findings of this kind" : "No findings recorded"}
                  description={
                    kindFilter
                      ? "This scan has no findings in the selected category. Clear the filter to see everything."
                      : "Run a discovery scan or import findings to populate this scan."
                  }
                  action={
                    <Button variant="outline" size="sm" onClick={() => setTab("scan")}>
                      Start a discovery scan
                    </Button>
                  }
                />
              </div>
            )}
          </CardContent>
        </Card>
      ) : null}

      {tab === "graph" && hasSession ? <GraphPanel scopeKey={scopeKey} ready={ready} /> : null}


      {tab === "dependencies" && hasSession ? (
        <Card>
          <CardHeader className="flex-row items-start justify-between">
            <div>
              <CardTitle>Discovered dependencies</CardTitle>
              <p className="mt-1 text-xs leading-5 text-muted-foreground">
                Packages declared by this scan, with the version actually requested and whether the dependency is
                runtime or test-only.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <label className="flex cursor-pointer items-center gap-2 text-xs text-muted-foreground">
                <input type="checkbox" className="accent-primary" checked={cryptoOnly} onChange={(event) => setCryptoOnly(event.target.checked)} />
                Crypto only
              </label>
              <RefreshButton onRefresh={() => dependencies.refetch()} aria-label="Refresh dependencies" variant="ghost" />
            </div>
          </CardHeader>
          <CardContent className="px-1">
            {dependencies.isLoading ? (
              <div className="p-4">
                <LoadingState label="Loading dependencies" />
              </div>
            ) : dependencies.isError && !isNoScanSelected(dependencies.error) ? (
              <div className="p-4">
                <ErrorState message={dependencies.error instanceof Error ? dependencies.error.message : undefined} onRetry={() => void dependencies.refetch()} />
              </div>
            ) : dependencyRows.length ? (
              <>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Package</TableHead>
                      <TableHead>Version</TableHead>
                      <TableHead>Ecosystem</TableHead>
                      <TableHead>Scope</TableHead>
                      <TableHead>Capability</TableHead>
                      <TableHead>Relevance</TableHead>
                      <TableHead>Graph</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                      {dependencyRows.map((dependency) => (
                        <TableRow key={dependency.id}>
                          <TableCell className="font-mono text-xs">{dependency.package}</TableCell>
                          <TableCell className="tnum text-xs text-muted-foreground">{dependency.version || "—"}</TableCell>
                          <TableCell className="text-xs text-muted-foreground">{titleCase(dependency.ecosystem)}</TableCell>
                          <TableCell>
                            <Badge variant={dependency.scope === "development" ? "muted" : "outline"} className="normal-case tracking-normal">
                              {dependency.scope === "development" ? "Dev" : "Runtime"}
                            </Badge>
                          </TableCell>
                        <TableCell className="text-xs">{dependency.capability || "—"}</TableCell>
                        <TableCell>
                          <RelevanceBadge relevance={dependency.relevance} />
                        </TableCell>
                        <TableCell className="text-[11px] text-muted-foreground">
                          <DependencyImpact
                            dependents={dependentsByNode.get(nodeIdByPackage.get(`${dependency.ecosystem}:${dependency.package}`) || "") || 0}
                            provides={providesByNode.get(nodeIdByPackage.get(`${dependency.ecosystem}:${dependency.package}`) || "") || 0}
                          />
                        </TableCell>
                        </TableRow>
                      ))}
                  </TableBody>
                </Table>
                <div className="flex flex-wrap items-center justify-between gap-3 border-t px-5 py-3 text-xs text-muted-foreground">
                  <span className="tnum">{formatNumber(dependencyTotal)} dependencies</span>
                  <span className="tnum">
                    {formatNumber(transitiveCount)} transitive links · {formatNumber(providesCount)} libraries mapped to assets
                  </span>
                  {keyServices.length ? <span>Key service: {keyServices.join(", ")}</span> : null}
                </div>
              </>
            ) : (
              <div className="p-4">
                <EmptyState
                  title={cryptoOnly ? "No cryptographic dependencies" : "No dependencies recorded"}
                  description={
                    cryptoOnly
                      ? "No manifest in this scan declares a cryptographically-relevant package."
                      : "Run a discovery scan over a project with a dependency manifest."
                  }
                  action={cryptoOnly ? null : (
                    <Button variant="outline" size="sm" onClick={() => setTab("scan")}>
                      Start a discovery scan
                    </Button>
                  )}
                />
              </div>
            )}
          </CardContent>
        </Card>
      ) : null}

      <Dialog
        open={reviewOpen}
        onOpenChange={setReviewOpen}
        title="Review discovery"
        description="Confirm the scope before starting. Discovery is read-only and covers the entire target."
        footer={
          <>
            <Button variant="ghost" onClick={() => setReviewOpen(false)}>
              Cancel
            </Button>
            <Button onClick={confirmScan} disabled={startScan.isPending}>
              {startScan.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" /> : <ScanLine className="h-3.5 w-3.5" aria-hidden="true" />}
              Start discovery
            </Button>
          </>
        }
      >
        <div className="space-y-3 text-sm">
          <ReviewRow label="Source" value="Imported findings" />
          <ReviewRow label="Sources" value={`${activeSources.length} selected: ${activeSources.map((s) => availableScanners.find((sc) => sc.source_type === s)?.name || s).join(", ")}`} />
          <ReviewRow label="Scope" value={scanScopeOptions.find((option) => option.value === scanType)?.label || titleCase(scanType)} />
          <ReviewRow label="Target" value={target.trim() || "Approved key locations"} mono />
          {limitFields.length ? (
            <ReviewRow
              label="Configured limits"
              value={limitFields
                .map(([key, field]) => {
                  const raw = limits[key];
                  const parsed = raw === undefined ? Number(field.default) : Number(raw);
                  return `${field.label}: ${formatNumber(Number.isFinite(parsed) ? parsed : 0)}`;
                })
                .join(" · ")}
            />
          ) : null}
          <div className="border bg-warning/5 p-3 text-xs leading-5 text-warning">
            <div className="flex gap-2">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
              Discovery records observations only. Risk classification, quantum exposure, and migration priorities are produced by later stages.
            </div>
          </div>
        </div>
      </Dialog>

      <Dialog
        open={browseOpen}
        onOpenChange={setBrowseOpen}
        title="Select discovery target"
        description="Choose a connected location to inspect."
        footer={
          <Button variant="outline" onClick={() => setBrowseOpen(false)}>
            Done
          </Button>
        }
      >
        <div className="space-y-3">
          <div className="flex gap-2">
            <Input value={browsePath} onChange={(event) => setBrowsePath(event.target.value)} placeholder="Root or location path" />
            <Button variant="outline" size="icon" onClick={() => setBrowsePath("")} aria-label="Show available locations">
              <Folder className="h-4 w-4" aria-hidden="true" />
            </Button>
          </div>
          {browse.isLoading ? (
            <LoadingState label="Reading locations" />
          ) : browse.isError ? (
            <ErrorState message={browse.error instanceof Error ? browse.error.message : undefined} onRetry={() => void browse.refetch()} />
          ) : browse.data?.error ? (
            <p className="text-xs text-destructive">{browse.data.error}</p>
          ) : (
            <div className="scrollbar-thin max-h-72 overflow-y-auto border">
              {browse.data?.folders?.length ? (
                browse.data.folders.map((folder) => (
                  <button
                    key={folder}
                    type="button"
                    className="flex w-full items-center gap-2 border-b px-3 py-2.5 text-left text-sm last:border-0 hover:bg-secondary"
                    onClick={() => {
                      const next = joinPath(browse.data?.path || browsePath, folder);
                      setBrowsePath(next);
                      setTarget(next);
                    }}
                  >
                    <Folder className="h-4 w-4 text-primary" aria-hidden="true" />
                    <span className="truncate">{folder}</span>
                  </button>
                ))
              ) : (
                <p className="p-4 text-xs text-muted-foreground">No further locations available.</p>
              )}
            </div>
          )}
        </div>
      </Dialog>
    </div>
  );
}

function ReviewRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-4">
      <span className="shrink-0 text-muted-foreground">{label}</span>
      <span className={mono ? "max-w-[280px] truncate text-right font-mono text-xs" : "text-right font-medium"} title={value}>
        {value}
      </span>
    </div>
  );
}

const RELEVANCE_VARIANTS: Record<string, BadgeProps["variant"]> = {
  core: "danger",
  supporting: "warning",
  adjacent: "muted",
  managed_key_service: "info",
  post_quantum: "success"
};

function DependencyImpact({ dependents, provides }: { dependents: number; provides: number }) {
  if (!dependents && !provides) {
    return <span className="text-muted-foreground">—</span>;
  }
  return (
    <div className="space-y-0.5">
      {dependents ? <p>{formatNumber(dependents)} depend{dependents === 1 ? "s" : ""} on it</p> : null}
      {provides ? <p>backs {formatNumber(provides)} asset{provides === 1 ? "" : "s"}</p> : null}
    </div>
  );
}

function RelevanceBadge({ relevance }: { relevance: string }) {
  if (!relevance) return <span className="text-xs text-muted-foreground">—</span>;
  return (
    <Badge variant={RELEVANCE_VARIANTS[relevance] || "muted"} className="normal-case tracking-normal">
      {relevance.replace(/_/g, " ")}
    </Badge>
  );
}

function EvidenceCell({ finding }: { finding: NormalizedFinding }) {
  const evidence = finding.evidence || {};
  const type = typeof evidence.type === "string" ? evidence.type : "unrecorded";
  const value = typeof evidence.value === "string" ? evidence.value : "";
  const strength = typeof evidence.strength === "string" ? evidence.strength : "";
  const line = finding.line ? `line ${finding.line}` : "";

  if (!value && !line) {
    return <span className="text-xs text-muted-foreground">—</span>;
  }

  return (
    <div className="space-y-0.5">
      <p className="truncate font-mono text-[11px]" title={value}>
        {value || type}
      </p>
      <p className="truncate text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
        {[type.replace(/_/g, " "), line].filter(Boolean).join(" · ")}
      </p>
      {strength ? (
        <p className="truncate text-[10px] uppercase tracking-[0.08em] text-warning">{strength.replace(/_/g, " ")}</p>
      ) : null}
    </div>
  );
}

function ConfidenceBadge({ value }: { value?: number | null }) {
  const level = confidenceLevel(value);
  return (
    <Badge variant={level.variant} className="normal-case tracking-normal">
      {level.label}
    </Badge>
  );
}

/**
 * One line saying whether this dataset can answer what the reasoning stage asks.
 *
 * The full contract check lived in its own tab that repeated counts, coverage and
 * a sample of the findings, all of which are already on this page and on the job
 * panel. This keeps the part nothing else states, and it states it compactly.
 */
function ContractStatus({ summary }: { summary?: Handoff }) {
  if (!summary) return null;
  const { contract, questions, counts } = summary;
  if (!counts.findings) return null;

  if (contract.satisfied) {
    return (
      <p className="mt-1.5 flex items-center gap-1.5 text-[11px] text-muted-foreground">
        <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
        <span>
          Every finding answers what, where, how, how confident, which asset, and what it depends
          on.
        </span>
      </p>
    );
  }

  const gaps = questions.filter((question) => question.unanswered > 0);
  return (
    <Tooltip
      msg={
        gaps.length
          ? gaps.map((gap) => `${gap.label} — ${formatNumber(gap.unanswered)} finding(s) cannot answer it`).join(" · ")
          : "The contract could not be verified for this dataset."
      }
    >
      <p className="mt-1.5 flex w-fit items-center gap-1.5 border border-amber-500/40 bg-amber-500/5 px-2 py-1 text-[11px] text-amber-700 dark:text-amber-400">
        <AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
        <span>
          {gaps.length
            ? `${gaps.length} question${gaps.length === 1 ? "" : "s"} not answerable by every finding`
            : "Contract not verified"}
        </span>
      </p>
    </Tooltip>
  );
}

/**
 * What a non-target scope will actually read, taken from the same resolver the
 * scanners use. A disabled target box plus a vague hint used to stand in for
 * this, which told the user nothing about the ten directories about to be read.
 *
 * The resolved preview is preferred over the registry's declared roots, and the
 * "Full tree" / "Selected" marker comes along with it. This replaced a second
 * "Connected scope" block that listed the very same paths directly beneath.
 */
function ScopeCoverage({
  scope,
  registry,
  preview
}: {
  scope: string;
  registry?: ScannerRegistry;
  preview?: ScanPreview;
}) {
  const info = registry?.scopes?.[scope as "quick" | "whole"];
  // The preview resolves the roots against this machine, so it wins whenever it
  // has loaded -- including when it resolved to nothing, which is the case that
  // must warn rather than fall back to the declared list and look fine.
  const roots = preview?.roots ?? info?.roots ?? [];
  if (!info && !roots.length) return null;

  return (
    <div className="border bg-muted/20 p-3">
      <p className="text-[11px] font-semibold uppercase tracking-[0.1em] text-muted-foreground">
        {roots.length} location{roots.length === 1 ? "" : "s"} will be read
      </p>
      {roots.length ? (
        <ul className="mt-2 max-h-32 space-y-0.5 overflow-y-auto pr-1">
          {roots.map((root) => (
            <li key={root.root} className="flex items-center justify-between gap-3 text-[11px]">
              <span className="truncate font-mono text-muted-foreground" title={root.root}>
                {root.root}
              </span>
              {"scan_all" in root ? (
                <span className="shrink-0 text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
                  {root.scan_all ? "Full tree" : "Selected"}
                </span>
              ) : null}
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-1 text-[11px] text-warning">
          None of these locations exist on this machine, so this scan would find nothing.
        </p>
      )}
      {info?.unbounded === false ? (
        <p className="mt-2 text-[11px] leading-4 text-muted-foreground">
          A ceiling is applied to this scope.
        </p>
      ) : null}
    </div>
  );
}

/** Human name for a source key, taken from the live scanner registry. */
function scannerName(scanners: ScannerDescriptor[], sourceType: string): string {
  return (
    scanners.find((scanner) => scanner.source_type === sourceType)?.name ||
    sourceType.replace(/_/g, " ")
  );
}

function BatchMonitor({ batch, scanners, onCancel, cancelling }: { batch: ScanBatch; scanners: ScannerDescriptor[]; onCancel: () => void; cancelling: boolean }) {
  const status = String(batch.status || "").toLowerCase();
  const active = BATCH_ACTIVE.has(status);
  const sources = batch.sources || [];
  const partial = sources.filter((source) => String(source.status).toLowerCase() === "partial");
  const skipped = sources.filter((source) => (source.items_skipped || 0) > 0);
  const nameFor = (source: string) => scannerName(scanners, source);

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between">
        <div className="min-w-0">
          <p className="font-mono text-xs text-muted-foreground">RUN #{batch.id}</p>
          <p className="mt-1 max-w-[320px] truncate text-sm font-medium" title={batch.target}>
            {batch.target || "Connected scope"}
          </p>
          <p className="mt-1 text-[11px] text-muted-foreground">
            {sources.length} source{sources.length === 1 ? "" : "s"} ·{" "}
            {formatNumber(batch.findings_count || 0)} finding
            {batch.findings_count === 1 ? "" : "s"}
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <StatusBadge status={batch.status} />
          {active ? (
            <Button variant="outline" size="sm" onClick={onCancel} disabled={cancelling}>
              {cancelling ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" /> : <XCircle className="h-3.5 w-3.5" aria-hidden="true" />}
              Cancel all
            </Button>
          ) : null}
        </div>
      </CardHeader>

      <div className="border-b px-5 pt-4">
        <Progress value={batch.progress} />
        <div className="flex justify-between py-2 text-[11px] text-muted-foreground">
          <span>{active ? "Sources running" : "All sources finished"}</span>
          <span className="tnum">{batch.progress}%</span>
        </div>
      </div>

      <CardContent className="px-1">
        <ul className="divide-y">
          {sources.map((source) => {
            const sourceStatus = String(source.status || "").toLowerCase();
            const reasons = source.skip_reason_labels || [];
            return (
              <li key={source.id} className="px-5 py-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="text-sm font-medium">{nameFor(source.source_type)}</p>
                      <StatusBadge status={source.status} />
                      {sourceStatus === "partial" ? (
                        <span className="text-[11px] text-warning">Incomplete coverage</span>
                      ) : null}
                    </div>
                    {typeof source.items_total === "number" && source.items_total > 0 ? (
                      <p className="tnum mt-1 text-[11px] text-muted-foreground">
                        {formatNumber(source.items_scanned || 0)} of{" "}
                        {formatNumber(source.items_total)} items inspected
                      </p>
                    ) : null}
                    {reasons.length ? (
                      <ul className="mt-1 space-y-0.5">
                        {reasons.map((reason) => (
                          <li key={reason.reason} className="text-[11px] text-warning">
                            {formatNumber(reason.count)} · {reason.label}
                          </li>
                        ))}
                      </ul>
                    ) : null}
                    {source.error && source.error_code !== "PARTIAL_COVERAGE" ? (
                      <p className="mt-1 text-[11px] leading-4 text-destructive">{source.error}</p>
                    ) : null}
                  </div>
                  <div className="flex shrink-0 items-center gap-3">
                    <span className="tnum text-[11px] text-muted-foreground">
                      {formatNumber(source.findings_count || 0)}
                    </span>
                    <span className="tnum w-10 text-right text-[11px] text-muted-foreground">
                      {source.progress}%
                    </span>
                  </div>
                </div>
              </li>
            );
          })}
        </ul>

        {batch.excluded?.length ? (
          <div className="border-t border-warning/30 bg-warning/5 px-5 py-3">
            <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-warning">
              Not run
            </p>
            <ul className="mt-1.5 space-y-1">
              {batch.excluded.map((item) => (
                <li key={item.source} className="text-[11px] leading-4 text-muted-foreground">
                  <span className="font-medium text-foreground">
                    {nameFor(item.source)}
                  </span>{" "}
                  — {item.reason}
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        {partial.length && !active ? (
          <p className="border-t px-5 py-3 text-[11px] leading-4 text-warning">
            {partial.length} source{partial.length === 1 ? "" : "s"} finished with incomplete
            coverage. Their findings are recorded; what they could not read is listed above.
          </p>
        ) : null}
        {skipped.length && !partial.length && !active ? (
          <p className="border-t px-5 py-3 text-[11px] leading-4 text-muted-foreground">
            Some items were not inspected. The run still reports only what was actually read.
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}


function JobMonitor({ job, isFetching, onCancel, cancelling }: { job: ScanJob; isFetching: boolean; onCancel: () => void; cancelling: boolean }) {
  const status = String(job.status || "").toLowerCase();
  const terminal = TERMINAL_STATUSES.has(status);
  const cancellable = CANCELLABLE_STATUSES.has(status);
  const outcome = jobOutcome(status);
  const demo = isDemoJob(job);

  return (
    <div className="space-y-4">
      {demo ? (
        <div className="flex items-center gap-2 border border-warning/30 bg-warning/5 px-3 py-2 text-[11px] font-medium uppercase tracking-[0.08em] text-warning">
          <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />
          Demo data
        </div>
      ) : null}

      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="font-mono text-xs text-muted-foreground">JOB #{job.id}</p>
          <p className="mt-1 max-w-[240px] truncate text-sm font-medium" title={job.target}>
            {job.target || "Connected scope"}
          </p>
        </div>
        <StatusBadge status={job.status} />
      </div>

      <Progress value={job.progress} />
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
        <span className="text-muted-foreground">
          {STAGE_LABELS[job.progress_stage || ""] ||
            (terminal ? "Reported progress" : isFetching ? "Refreshing state…" : "Current progress")}
        </span>
        <span className="tnum font-medium">{job.progress}%</span>
      </div>

      {typeof job.items_total === "number" && job.items_total > 0 ? (
        <p className="tnum text-[11px] text-muted-foreground">
          {formatNumber(job.items_scanned || 0)} of {formatNumber(job.items_total)} items inspected
          {job.items_skipped ? ` · ${formatNumber(job.items_skipped)} not inspected` : ""}
        </p>
      ) : !terminal && job.progress_stage === "enumerating" ? (
        <p className="text-[11px] text-muted-foreground">Counting items in scope…</p>
      ) : null}

      {status === "partial" && (job.skip_reason_labels?.length || job.items_skipped) ? (
        <div className="border border-warning/40 bg-warning/5 p-3">
          <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-warning">
            What was not inspected
          </p>
          <ul className="mt-2 space-y-1">
            {(job.skip_reason_labels || []).map((entry) => (
              <li key={entry.reason} className="flex items-baseline justify-between gap-3 text-[11px]">
                <span className="text-muted-foreground">{entry.label}</span>
                <span className="tnum shrink-0 text-warning">{formatNumber(entry.count)}</span>
              </li>
            ))}
            {!job.skip_reason_labels?.length ? (
              <li className="flex items-baseline justify-between gap-3 text-[11px]">
                <span className="text-muted-foreground">Items could not be inspected</span>
                <span className="tnum shrink-0 text-warning">{formatNumber(job.items_skipped || 0)}</span>
              </li>
            ) : null}
          </ul>
          {job.error_action ? (
            <p className="mt-2 text-[11px] leading-4 text-muted-foreground">{job.error_action}</p>
          ) : null}
        </div>
      ) : null}

      <div className="grid grid-cols-2 gap-3 border-t pt-4 text-xs">
        <div>
          <p className="text-muted-foreground">Findings</p>
          <p className="tnum mt-1 font-medium">{formatNumber(job.findings_count)}</p>
        </div>
        <div>
          <p className="text-muted-foreground">Created</p>
          <p className="mt-1">{formatDate(job.created_at)}</p>
        </div>
      </div>

      {job.error ? (
        <div
          className={
            status === "failed"
              ? "space-y-1 border border-destructive/30 bg-destructive/5 p-3 text-xs leading-5 text-destructive"
              : "space-y-1 border border-border bg-muted/20 p-3 text-xs leading-5 text-muted-foreground"
          }
        >
          <div className="flex gap-2">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
            <span>{job.error}</span>
          </div>
          {job.error_action ? <p className="pl-6 opacity-80">{job.error_action}</p> : null}
          {job.error_code ? <p className="pl-6 font-mono text-[10px] uppercase opacity-70">{job.error_code}</p> : null}
        </div>
      ) : null}

      {cancellable ? (
        <Button variant="outline" className="w-full" onClick={onCancel} disabled={cancelling}>
          {cancelling ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" /> : <XCircle className="h-3.5 w-3.5" aria-hidden="true" />}
          {cancelling ? "Cancelling…" : "Cancel discovery"}
        </Button>
      ) : null}

      {outcome ? (
        <div
          className={
            outcome.variant === "success"
              ? "flex items-center gap-2 border border-success/30 bg-success/5 p-3 text-xs text-success"
              : outcome.variant === "danger"
                ? "flex items-center gap-2 border border-destructive/30 bg-destructive/5 p-3 text-xs text-destructive"
                : outcome.variant === "warning"
                  ? "flex items-center gap-2 border border-warning/30 bg-warning/5 p-3 text-xs text-warning"
                  : "flex items-center gap-2 border border-border bg-muted/20 p-3 text-xs text-muted-foreground"
          }
        >
          {outcome.variant === "success" ? <CheckCircle2 className="h-4 w-4 shrink-0" aria-hidden="true" /> : <AlertTriangle className="h-4 w-4 shrink-0" aria-hidden="true" />}
          <span>
            <span className="font-medium">{outcome.title}.</span> {outcome.detail}
          </span>
        </div>
      ) : null}
    </div>
  );
}
