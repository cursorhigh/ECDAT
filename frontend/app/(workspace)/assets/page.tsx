"use client";

import { FormEvent, useEffect, useRef, useState, type ReactNode } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Boxes, ChevronLeft, ChevronRight, ExternalLink, Filter, Info, Loader2, Search, Sparkles, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { Input, Label, Select } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { CopyButton } from "@/components/data/copy-button";
import { EmptyState, ErrorState, LoadingState } from "@/components/feedback/data-state";
import { PageHeader } from "@/components/data/page-header";
import { Tabs } from "@/components/ui/tabs";
import { NavTooltip } from "@/components/ui/nav-tooltip";
import { GraphPanel } from "@/components/data/graph-panel";
import { DependenciesPanel } from "@/components/data/dependencies-panel";
import { evaluateRiskGate, RiskReadinessNote } from "@/components/data/risk-start-dialog";
import { requestRiskPrompt } from "@/components/data/risk-prompt-store";
import { StatusBadge } from "@/components/data/status-badge";
import { api } from "@/lib/api/client";
import type { Asset } from "@/lib/api/types";
import { useToast } from "@/components/feedback/toast";
import { useSession } from "@/lib/session-context";
import { formatDate, formatNumber, titleCase, truncate } from "@/lib/utils";

const ASSET_TYPES = [
  "application",
  "repository",
  "source_code",
  "binary",
  "firmware",
  "container",
  "library",
  "dependency",
  "certificate",
  "key_reference",
  "cloud_resource",
  "infrastructure",
  "hardware",
  "network_endpoint",
  "external_service",
  "api",
  "unknown"
];

export default function AssetsPage() {
  const { ready, scopeKey, info , hasSession } = useSession();
  const { pushToast } = useToast();
  const [searchInput, setSearchInput] = useState("");
  const [search, setSearch] = useState("");
  const [assetType, setAssetType] = useState("");
  const [ordering, setOrdering] = useState("name");
  const [page, setPage] = useState(1);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [sightingsId, setSightingsId] = useState<number | null>(null);
  const [tab, setTab] = useState("inventory");
  const searchFieldRef = useRef<HTMLInputElement | null>(null);

  // Live search. Typing filters as you go rather than requiring a submit, and
  // the debounce keeps a fast typist from firing a query per keystroke.
  useEffect(() => {
    const next = searchInput.trim();
    if (next === search) return;
    const timer = setTimeout(() => {
      setSearch(next);
      setPage(1);
    }, 280);
    return () => clearTimeout(timer);
  }, [searchInput, search]);
  const scans = useQuery({
    queryKey: ["scans", scopeKey],
    // Widened because the API pages at 25 and orders newest-first: a session with
    // many in-flight scans could otherwise hide a completed one off page 1 and
    // wrongly lock the gate.
    queryFn: () => api.scans({ page_size: 100 }),
    enabled: ready && hasSession
  });
  const riskGate = evaluateRiskGate(scans.data?.results, hasSession);

  /**
   * Pressing the button asks the single global prompt to open.
   *
   * This page used to park the run and render its own copy of the dialog, which
   * is what produced two identical modals: the assets page and the global prompt
   * were independent mounts, and only this one registered with the dedupe store.
   * Parking and opening are now both the prompt's job, so a button press and a
   * scan completing on its own produce the same single modal.
   */
  const beginRisk = useMutation({
    mutationFn: () => {
      const scanId = riskGate.analyzable[0]?.id;
      if (!scanId) throw new Error("No completed scan is available to analyze.");
      return Promise.resolve(scanId);
    },
    onSuccess: (scanId) => {
      requestRiskPrompt({ kind: "start", scanJobId: scanId });
    },
    onError: (error) =>
      pushToast(error instanceof Error ? error.message : "Could not start risk analysis.", "error")
  });

  const beginRiskAnalysis = async () => {
    try {
      await beginRisk.mutateAsync();
    } catch {
      // onError already surfaced it.
    }
  };
  const assets = useQuery({
    queryKey: ["assets", scopeKey, search, assetType, ordering, page],
    queryFn: () => api.assets({ search: search || undefined, asset_type: assetType || undefined, ordering, page }),
    enabled: ready && hasSession
  });
  const selected = useQuery({ queryKey: ["asset", selectedId, scopeKey], queryFn: () => api.asset(selectedId!), enabled: Boolean(selectedId) });
  const sightings = useQuery({ queryKey: ["occurrences", sightingsId, scopeKey], queryFn: () => api.occurrences(sightingsId!), enabled: Boolean(sightingsId) });

  const submitSearch = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSearch(searchInput.trim());
    setPage(1);
  };
  const changeOrdering = (value: string) => { setOrdering(value); setPage(1); };
  const changeAssetType = (value: string) => { setAssetType(value); setPage(1); };
  const clearFilters = () => { setSearchInput(""); setSearch(""); setAssetType(""); setPage(1); };

  // "/" focuses search, Escape clears the term. Same shortcut the graph search
  // uses, so it is consistent across the workspace.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "/" && tab !== "inventory") return;
      const target = event.target as HTMLElement | null;
      const typing = target && /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName);
      if (event.key === "/" && !typing) {
        event.preventDefault();
        searchFieldRef.current?.focus();
      } else if (event.key === "Escape" && document.activeElement === searchFieldRef.current) {
        setSearchInput("");
        setSearch("");
        setPage(1);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [tab]);

  const total = assets.data?.count || 0;
  const start = total ? (page - 1) * 25 + 1 : 0;
  const end = total ? Math.min(page * 25, total) : 0;
  const hasFilters = Boolean(search || assetType);

  return (
    <div className="space-y-6">
      <PageHeader
        compact
        eyebrow="Inventory segment"
        title="Discovered assets"
        description="What the scan found, and how it is related: the asset inventory, the relationship graph, and the declared packages behind them."
        actions={
          <div className="flex items-center gap-2">
            <NavTooltip
              title={`${formatNumber(total)} indexed in scope`}
              description="Distinct cryptographic objects that discovery resolved. One asset can be seen in many places — the sightings count shows how many."
            >
              <span className="flex cursor-help items-center gap-2 border bg-card px-3 py-2 text-xs text-muted-foreground">
                <Boxes className="h-4 w-4 text-primary" aria-hidden="true" />
                {formatNumber(total)} indexed in scope
                <Info className="h-3 w-3 opacity-60" aria-hidden="true" />
              </span>
            </NavTooltip>
            {/* Custom tooltip rather than a native `title`: browsers suppress
                title on a disabled button, so the reason the action is locked
                was invisible exactly when it was needed. */}
            <NavTooltip
              title={riskGate.locked ? "Risk analysis is locked" : "Run risk analysis"}
              description={riskGate.reason || "Start the assessment, then answer a few questions about your data and timeline."}
            >
              <span className="inline-flex">
                <Button
                  size="sm"
                  onClick={() => void beginRiskAnalysis()}
                  disabled={riskGate.locked || beginRisk.isPending}
                >
                  {beginRisk.isPending ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                  ) : (
                    <Sparkles className="h-3.5 w-3.5" aria-hidden="true" />
                  )}
                  Run Risk Analysis
                </Button>
              </span>
            </NavTooltip>
          </div>
        }
      />

      <RiskReadinessNote gate={riskGate} />

      <Tabs
        value={tab}
        onValueChange={setTab}
        items={[
          { value: "inventory", label: "Inventory" },
          { value: "graph", label: "Graph" },
          { value: "dependencies", label: "Dependencies" }
        ]}
      />

      {tab !== "inventory" ? (
        tab === "graph" ? (
          <GraphPanel scopeKey={scopeKey} ready={ready} />
        ) : (
          <DependenciesPanel scopeKey={scopeKey} ready={ready} />
        )
      ) : null}
      {tab === "inventory" ? (
        <>
        {/* Search + filter in one compact strip. Search is live and debounced,
            so the Submit button is only a keyboard affordance, not a gate. */}
        <Card>
          <CardContent className="px-3 py-2.5">
            <div className="flex flex-col gap-2 lg:flex-row lg:items-center">
              <form onSubmit={submitSearch} className="flex min-w-0 flex-1 gap-2">
                <div className="relative min-w-0 flex-1">
                  <Search className="pointer-events-none absolute left-2.5 top-2 h-3.5 w-3.5 text-muted-foreground" aria-hidden="true" />
                  <Input
                    ref={searchFieldRef}
                    value={searchInput}
                    onChange={(event) => setSearchInput(event.target.value)}
                    placeholder="Search name, algorithm, location or owner"
                    className="h-8 pl-8 pr-14 text-xs"
                    aria-label="Search cryptographic assets"
                  />
                  {searchInput ? (
                    <button
                      type="button"
                      onClick={() => { setSearchInput(""); setSearch(""); setPage(1); }}
                      className="absolute right-2 top-1.5 text-muted-foreground transition-colors hover:text-foreground"
                      aria-label="Clear search"
                    >
                      <X className="h-3.5 w-3.5" aria-hidden="true" />
                    </button>
                  ) : (
                    <kbd className="pointer-events-none absolute right-2 top-1.5 border bg-muted px-1 font-mono text-[10px] leading-4 text-muted-foreground">/</kbd>
                  )}
                </div>
              </form>

              <div className="flex flex-wrap items-center gap-2">
                <Label htmlFor="asset-type" className="sr-only">Filter by asset type</Label>
                <Select
                  id="asset-type"
                  value={assetType}
                  onChange={(event) => changeAssetType(event.target.value)}
                  className="h-8 w-40 text-xs"
                >
                  <option value="">All types</option>
                  {ASSET_TYPES.map((type) => <option key={type} value={type}>{titleCase(type)}</option>)}
                </Select>
                <Label htmlFor="asset-order" className="sr-only">Sort assets</Label>
                <Select
                  id="asset-order"
                  value={ordering}
                  onChange={(event) => changeOrdering(event.target.value)}
                  className="h-8 w-40 text-xs"
                >
                  <option value="name">Name A→Z</option>
                  <option value="-name">Name Z→A</option>
                  <option value="family">Family A→Z</option>
                  <option value="-family">Family Z→A</option>
                  <option value="key_size">Key size ↑</option>
                  <option value="-key_size">Key size ↓</option>
                </Select>
              </div>
            </div>

            {/* Active filters, each individually removable. The old bar only
                offered one "Clear" that reset everything at once. */}
            {hasFilters ? (
              <div className="mt-2 flex flex-wrap items-center gap-1.5 border-t pt-2">
                <span className="text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground">Filtered by</span>
                {search ? (
                  <FilterChip label={`“${truncate(search, 28)}”`} onClear={() => { setSearchInput(""); setSearch(""); setPage(1); }} />
                ) : null}
                {assetType ? (
                  <FilterChip label={titleCase(assetType)} onClear={() => changeAssetType("")} />
                ) : null}
                <Button type="button" variant="ghost" size="sm" className="h-6 px-1.5 text-[11px]" onClick={clearFilters}>
                  Clear all
                </Button>
              </div>
            ) : null}
          </CardContent>
        </Card>

        <Card><CardHeader className="flex-row items-center justify-between py-2.5"><div><CardTitle>Asset inventory</CardTitle><p className="mt-1 text-xs text-muted-foreground">{search ? <>Results matching <span className="font-mono">“{search}”</span> in {info?.session_name || "this scan"}.</> : "Every asset returned by the active inventory query."}</p></div><div className="flex items-center gap-2 text-xs text-muted-foreground"><Filter className="h-3.5 w-3.5" aria-hidden="true" />{start ? `${start}–${end}` : "0"} of {formatNumber(total)}</div></CardHeader><CardContent className="p-0">{assets.isLoading ? <div className="p-4"><LoadingState label="Loading asset inventory" /></div> : assets.isError ? <div className="p-4"><ErrorState message={assets.error instanceof Error ? assets.error.message : undefined} onRetry={() => void assets.refetch()} /></div> : assets.data?.results?.length ? <Table><TableHeader><TableRow><TableHead>Asset</TableHead><TableHead>Family / algorithm</TableHead><TableHead>Key details</TableHead><TableHead>Location</TableHead><TableHead>Owner</TableHead><TableHead>Inventory state</TableHead><TableHead /></TableRow></TableHeader><TableBody>{assets.data.results.map((asset) => <AssetRow key={asset.id} asset={asset} onOpen={() => setSelectedId(asset.id)} onShowSightings={() => setSightingsId(asset.id)} />)}</TableBody></Table> : <div className="p-4"><EmptyState title="No assets in this query" description={search ? "Try a different search term or clear the search to inspect the full inventory." : "Run a discovery job to populate the cryptographic asset inventory."} /></div>}</CardContent><div className="flex items-center justify-between border-t px-4 py-2"><p className="text-[11px] text-muted-foreground">Page {page}</p><div className="flex gap-2"><Button variant="outline" size="sm" disabled={!assets.data?.previous || page <= 1} onClick={() => setPage((value) => Math.max(1, value - 1))}><ChevronLeft className="h-3.5 w-3.5" aria-hidden="true" />Previous</Button><Button variant="outline" size="sm" disabled={!assets.data?.next} onClick={() => setPage((value) => value + 1)}>Next<ChevronRight className="h-3.5 w-3.5" aria-hidden="true" /></Button></div></div></Card>

        </>
      ) : null}
      <Dialog open={Boolean(selectedId)} onOpenChange={(open) => { if (!open) setSelectedId(null); }} title="Asset details" description="Read-only inventory metadata for the active scope." className="max-w-2xl"><AssetDetail asset={selected.data} loading={selected.isLoading} error={selected.error instanceof Error ? selected.error.message : undefined} /></Dialog>

      <Dialog
        open={Boolean(sightingsId)}
        onOpenChange={(open) => { if (!open) setSightingsId(null); }}
        title="Where this was detected"
        description="Every place this asset was observed, most recent first."
        className="max-w-2xl"
      >
        {sightings.isLoading ? (
          <LoadingState label="Loading sightings" />
        ) : sightings.isError ? (
          <ErrorState
            message={sightings.error instanceof Error ? sightings.error.message : undefined}
            onRetry={() => void sightings.refetch()}
          />
        ) : sightings.data?.results?.length ? (
          /* Capped and scrollable. A scan can record hundreds of locations for
             one asset, and an uncapped list pushed the dialog past the viewport
             so its own footer and the Close button were unreachable. */
          <div className="scrollbar-thin -mx-1 max-h-[52vh] overflow-y-auto px-1">
            <div className="divide-y">
              {sightings.data.results.map((occurrence) => (
                <div key={occurrence.id} className="flex items-start justify-between gap-4 py-2.5 first:pt-0 last:pb-0">
                  <div className="min-w-0">
                    <CellTip
                      label={occurrence.location ? "Full location" : "Not reported"}
                      description={occurrence.location || undefined}
                    >
                      <span className="block truncate font-mono text-xs">
                        {occurrence.location || "Location not reported"}
                      </span>
                    </CellTip>
                    <span className="mt-0.5 block text-[11px] text-muted-foreground">
                      {occurrence.line ? `Line ${occurrence.line} · ` : ""}
                      Last seen {formatDate(occurrence.last_seen)}
                    </span>
                  </div>
                  {occurrence.scan_job ? (
                    <span className="shrink-0 font-mono text-[11px] text-muted-foreground">
                      Job #{occurrence.scan_job}
                    </span>
                  ) : null}
                </div>
              ))}
            </div>
          </div>
        ) : (
          <EmptyState
            title="No sightings recorded"
            description="This asset has no recorded detection locations in the current scope."
          />
        )}
      </Dialog>
    </div>
  );
}

function FilterChip({ label, onClear }: { label: string; onClear: () => void }) {
  return (
    <span className="inline-flex items-center gap-1 border border-primary/40 bg-primary/5 py-0.5 pl-2 pr-1 text-[11px]">
      {label}
      <button
        type="button"
        onClick={onClear}
        className="text-muted-foreground transition-colors hover:text-foreground"
        aria-label={`Remove filter ${label}`}
      >
        <X className="h-3 w-3" aria-hidden="true" />
      </button>
    </span>
  );
}

/**
 * A table cell whose visible text is shortened, with the full value on hover.
 *
 * The inventory paths are long absolute Windows paths and algorithm strings are
 * often longer than the column, so the row has to truncate somewhere. Truncating
 * with only a `title` attribute loses the explanation; these carry what the
 * truncated text actually meant.
 */
function CellTip({ label, description, children }: { label: string; description: ReactNode; children: ReactNode }) {
  if (!description) return <>{children}</>;
  return (
    <NavTooltip title={label} description={description}>
      <span className="cursor-help">{children}</span>
    </NavTooltip>
  );
}

function AssetRow({ asset, onOpen, onShowSightings }: { asset: Asset; onOpen: () => void; onShowSightings: () => void }) {
  // Full path for the tooltip, but the filename is what identifies a hit, so it
  // leads and the containing folder is shown underneath rather than a mid-path
  // slice that reads as noise.
  const fullPath = asset.location || "";
  const separator = Math.max(fullPath.lastIndexOf("\\"), fullPath.lastIndexOf("/"));
  const fileName = separator >= 0 ? fullPath.slice(separator + 1) : fullPath;
  const parentDir = separator >= 0 ? fullPath.slice(0, separator) : "";

  const familyLabel = asset.family_display || titleCase(asset.family || "unknown");
  const keyDetails = [
    asset.key_size ? `${asset.key_size} bits` : null,
    asset.curve || null,
    asset.protocol || null,
    asset.library ? `library: ${asset.library}${asset.library_version ? ` ${asset.library_version}` : ""}` : null
  ].filter(Boolean) as string[];

  return (
    <TableRow>
      <TableCell>
        {/* Name and sightings are siblings: a <button> inside a <button> is
            invalid HTML and breaks hydration. The name uses a block <span>
            rather than <p> because a button may only contain phrasing. */}
        <button type="button" onClick={onOpen} className="block w-full text-left">
          <CellTip
            label={asset.name}
            description={
              <>
                {asset.identifier ? <span className="block font-mono text-[10px]">identifier {asset.identifier}</span> : null}
                {asset.environment ? <span className="block">environment {asset.environment}</span> : null}
                <span className="block">opened from the full record</span>
              </>
            }
          >
            <span className="font-medium hover:text-primary">{asset.name}</span>
          </CellTip>
        </button>
        <div className="mt-0.5 flex flex-wrap items-center gap-1.5">
          <span className="font-mono text-[11px] text-muted-foreground">#{asset.id}</span>
          {asset.asset_type_display ? (
            <Badge variant="outline" className="normal-case tracking-normal">{asset.asset_type_display}</Badge>
          ) : null}
          {asset.occurrence_count ? (
            <button
              type="button"
              // preventDefault + stopPropagation: this is a sibling of the name
              // button, not a child, so the click should already be scoped --
              // but stopping it here guarantees it can never reach a row-level
              // handler and open the detail dialog behind the sightings one.
              onClick={(event) => {
                event.preventDefault();
                event.stopPropagation();
                onShowSightings();
              }}
              aria-label={`Show the ${asset.occurrence_count} locations where ${asset.name} was detected`}
              className="mt-0.5 text-[10px] uppercase tracking-[0.08em] text-primary hover:underline"
            >
              {asset.occurrence_count} sighting{asset.occurrence_count === 1 ? "" : "s"}
            </button>
          ) : null}
        </div>
      </TableCell>

      <TableCell>
        {/* One tooltip per cell. This used to wrap the family and the algorithm
            in two separate triggers, so hovering produced whichever bubble the
            pointer happened to be over -- two tooltips for one value. */}
        <CellTip
          label={familyLabel}
          description={
            <>
              {asset.algorithm ? (
                <span className="block">algorithm: {asset.algorithm}</span>
              ) : (
                <span className="block">no algorithm recorded</span>
              )}
              {asset.family && asset.family !== asset.family_display ? (
                <span className="block">family: {asset.family}</span>
              ) : null}
            </>
          }
        >
          <span className="block truncate text-sm">{familyLabel}</span>
          <span className="mt-0.5 block truncate font-mono text-[11px] text-muted-foreground">
            {asset.algorithm || "Algorithm not reported"}
          </span>
        </CellTip>
      </TableCell>

      <TableCell>
        <CellTip
          label={keyDetails.length ? keyDetails.join(" · ") : "No key details reported"}
          description={
            asset.library_version
              ? `${asset.library} ${asset.library_version}`
              : asset.library || undefined
          }
        >
          <span className="block font-mono text-xs">
            {asset.key_size ? `${asset.key_size} bits` : "—"}
          </span>
          <span className="mt-0.5 block truncate text-[11px] text-muted-foreground">
            {asset.curve || asset.protocol || asset.library || "No curve/protocol"}
          </span>
        </CellTip>
      </TableCell>

      <TableCell>
        {fullPath ? (
          <CellTip
            label={fileName}
            description={
              <>
                <span className="block font-mono text-[10px] leading-4">{fullPath}</span>
                {parentDir ? <span className="mt-1 block text-[10px] leading-4 text-muted-foreground">found in {parentDir}</span> : null}
                {asset.occurrence_count ? (
                  <span className="mt-1 block text-[10px] leading-4 text-muted-foreground">
                    seen in {asset.occurrence_count} location{asset.occurrence_count === 1 ? "" : "s"}
                  </span>
                ) : null}
              </>
            }
          >
            <span className="block truncate font-mono text-[11px]">{fileName || "—"}</span>
            {parentDir ? (
              <span className="mt-0.5 block truncate font-mono text-[10px] text-muted-foreground">
                {truncate(parentDir, 40)}
              </span>
            ) : null}
          </CellTip>
        ) : (
          <span className="text-[11px] text-muted-foreground">Location not reported</span>
        )}
      </TableCell>

      <TableCell>
        <CellTip
          label={asset.owner || "Unassigned"}
          description={asset.owner ? undefined : "No owner was recorded for this asset."}
        >
          <span className="block truncate text-xs text-muted-foreground">{asset.owner || "Unassigned"}</span>
        </CellTip>
      </TableCell>

      <TableCell>
        <CellTip
          label={asset.inventory_status_display || asset.inventory_status || "Unknown"}
          description="Whether this asset is still live, superseded or retired."
        >
          <StatusBadge status={asset.inventory_status} />
        </CellTip>
      </TableCell>

      <TableCell>
        <Button variant="ghost" size="icon-sm" onClick={onOpen} aria-label={`Open details for ${asset.name}`}>
          <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
        </Button>
      </TableCell>
    </TableRow>
  );
}

function AssetDetail({ asset, loading, error }: { asset?: Asset; loading: boolean; error?: string }) {
  if (loading) return <LoadingState label="Loading asset detail" />;
  if (error) return <ErrorState message={error} />;
  if (!asset) return <EmptyState title="Asset unavailable" description="The asset is not present in the active scope." />;
  const fields: Array<[string, string | null | undefined]> = [["Asset type", titleCase(asset.asset_type_display || asset.asset_type)], ["Family", titleCase(asset.family_display || asset.family)], ["Algorithm", asset.algorithm], ["Key size", asset.key_size ? `${asset.key_size} bits` : null], ["Curve", asset.curve], ["Protocol", asset.protocol], ["Library", asset.library], ["Library version", asset.library_version], ["Source type", titleCase(asset.source_type)], ["Identifier", asset.identifier], ["Sightings", asset.occurrence_count ? String(asset.occurrence_count) : null], ["Owner", asset.owner], ["Inventory state", titleCase(asset.inventory_status_display || asset.inventory_status)], ["Created", formatDate(asset.created_at)]];
  return <div className="space-y-5"><div className="flex items-start justify-between gap-4 border bg-muted/20 p-4"><div className="min-w-0"><p className="text-lg font-semibold">{asset.name}</p><p className="mt-1 font-mono text-xs text-muted-foreground">Asset #{asset.id}</p></div><StatusBadge status={asset.inventory_status} /></div><div><SectionDetail label="Location" value={asset.location || "No location reported"} copyValue={asset.location || undefined} /></div><div className="grid gap-x-6 gap-y-4 sm:grid-cols-2">{fields.map(([label, value]) => <div key={label}><p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{label}</p><p className="mt-1 text-sm">{value || "—"}</p></div>)}</div><p className="border-t pt-4 text-[11px] leading-5 text-muted-foreground">Related findings, assessments, and mitigation references are available from the analysis and mitigation pages.</p></div>;
}

function SectionDetail({ label, value, copyValue }: { label: string; value: string; copyValue?: string }) {
  return <div className="flex items-start justify-between gap-3"><div className="min-w-0"><p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{label}</p><p className="mt-1 break-all font-mono text-xs">{value}</p></div>{copyValue ? <CopyButton value={copyValue} label="Copy location" /> : null}</div>;
}
