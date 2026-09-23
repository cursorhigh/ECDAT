"use client";

import { FormEvent, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Boxes, ChevronLeft, ChevronRight, ExternalLink, Filter, Search, SlidersHorizontal, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { Input, Label, Select } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { CopyButton } from "@/components/data/copy-button";
import { EmptyState, ErrorState, LoadingState } from "@/components/feedback/data-state";
import { PageHeader } from "@/components/data/page-header";
import { StatusBadge } from "@/components/data/status-badge";
import { api } from "@/lib/api/client";
import type { Asset } from "@/lib/api/types";
import { useSession } from "@/lib/session-context";
import { formatDate, formatNumber, titleCase, truncate } from "@/lib/utils";

export default function AssetsPage() {
  const { ready, scopeKey, info } = useSession();
  const [searchInput, setSearchInput] = useState("");
  const [search, setSearch] = useState("");
  const [ordering, setOrdering] = useState("name");
  const [page, setPage] = useState(1);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const assets = useQuery({ queryKey: ["assets", scopeKey, search, ordering, page], queryFn: () => api.assets({ search: search || undefined, ordering, page }), enabled: ready });
  const selected = useQuery({ queryKey: ["asset", selectedId, scopeKey], queryFn: () => api.asset(selectedId!), enabled: Boolean(selectedId) });

  const submitSearch = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); setPage(1); setSearch(searchInput.trim()); };
  const changeOrdering = (value: string) => { setOrdering(value); setPage(1); };
  const total = assets.data?.count || 0;
  const start = total ? (page - 1) * 25 + 1 : 0;
  const end = total ? Math.min(page * 25, total) : 0;

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Inventory segment" title="Cryptographic assets" description="Search the backend inventory, inspect provenance, and trace technical values before analysis. Search and ordering are sent to the Django API." actions={<div className="flex items-center gap-2 border bg-card px-3 py-2 text-xs text-muted-foreground"><Boxes className="h-4 w-4 text-primary" aria-hidden="true" />{formatNumber(total)} indexed in scope</div>} />
      <Card><CardContent className="p-4"><div className="flex flex-col gap-3 lg:flex-row lg:items-end"><form onSubmit={submitSearch} className="flex min-w-0 flex-1 gap-2"><div className="relative min-w-0 flex-1"><Search className="pointer-events-none absolute left-3 top-3 h-4 w-4 text-muted-foreground" aria-hidden="true" /><Input value={searchInput} onChange={(event) => setSearchInput(event.target.value)} placeholder="Search name, algorithm, location, or owner" className="pl-9" aria-label="Search cryptographic assets" /></div><Button type="submit" variant="secondary">Search</Button>{search ? <Button type="button" variant="ghost" size="icon" onClick={() => { setSearchInput(""); setSearch(""); setPage(1); }} aria-label="Clear asset search"><X className="h-4 w-4" aria-hidden="true" /></Button> : null}</form><div className="flex items-center gap-2"><div className="flex items-center gap-2"><SlidersHorizontal className="h-4 w-4 text-muted-foreground" aria-hidden="true" /><Label htmlFor="asset-order" className="sr-only">Sort assets</Label><Select id="asset-order" value={ordering} onChange={(event) => changeOrdering(event.target.value)} className="w-44"><option value="name">Name ascending</option><option value="-name">Name descending</option><option value="family">Family ascending</option><option value="-family">Family descending</option><option value="key_size">Key size ascending</option><option value="-key_size">Key size descending</option></Select></div><span className="hidden text-xs text-muted-foreground md:inline">Server-supported filters only</span></div></div></CardContent></Card>

      <Card><CardHeader className="flex-row items-center justify-between"><div><CardTitle>Asset inventory</CardTitle><p className="mt-1 text-xs text-muted-foreground">{search ? <>Results matching <span className="font-mono">“{search}”</span> in {info?.session_name || "All data"}.</> : "Every asset returned by the active inventory query."}</p></div><div className="flex items-center gap-2 text-xs text-muted-foreground"><Filter className="h-3.5 w-3.5" aria-hidden="true" />{start ? `${start}–${end}` : "0"} of {formatNumber(total)}</div></CardHeader><CardContent className="p-0">{assets.isLoading ? <div className="p-5"><LoadingState label="Loading asset inventory" /></div> : assets.isError ? <div className="p-5"><ErrorState message={assets.error instanceof Error ? assets.error.message : undefined} onRetry={() => void assets.refetch()} /></div> : assets.data?.results?.length ? <Table><TableHeader><TableRow><TableHead>Asset</TableHead><TableHead>Family / algorithm</TableHead><TableHead>Key details</TableHead><TableHead>Location</TableHead><TableHead>Owner</TableHead><TableHead>Inventory state</TableHead><TableHead /></TableRow></TableHeader><TableBody>{assets.data.results.map((asset) => <AssetRow key={asset.id} asset={asset} onOpen={() => setSelectedId(asset.id)} />)}</TableBody></Table> : <div className="p-5"><EmptyState title="No assets in this query" description={search ? "Try a different search term or clear the search to inspect the full inventory." : "Run a discovery job to populate the cryptographic asset inventory."} /></div>}</CardContent><div className="flex items-center justify-between border-t px-5 py-3"><p className="text-[11px] text-muted-foreground">Page {page}</p><div className="flex gap-2"><Button variant="outline" size="sm" disabled={!assets.data?.previous || page <= 1} onClick={() => setPage((value) => Math.max(1, value - 1))}><ChevronLeft className="h-3.5 w-3.5" aria-hidden="true" />Previous</Button><Button variant="outline" size="sm" disabled={!assets.data?.next} onClick={() => setPage((value) => value + 1)}>Next<ChevronRight className="h-3.5 w-3.5" aria-hidden="true" /></Button></div></div></Card>

      <Dialog open={Boolean(selectedId)} onOpenChange={(open) => { if (!open) setSelectedId(null); }} title="Asset details" description="Read-only inventory metadata returned by the Django API." className="max-w-2xl"><AssetDetail asset={selected.data} loading={selected.isLoading} error={selected.error instanceof Error ? selected.error.message : undefined} /></Dialog>
    </div>
  );
}

function AssetRow({ asset, onOpen }: { asset: Asset; onOpen: () => void }) {
  return <TableRow><TableCell><button type="button" onClick={onOpen} className="text-left"><p className="font-medium hover:text-primary">{asset.name}</p><p className="mt-0.5 font-mono text-[11px] text-muted-foreground">#{asset.id}</p></button></TableCell><TableCell><p className="text-sm">{titleCase(asset.family_display || asset.family)}</p><p className="mt-0.5 font-mono text-[11px] text-muted-foreground">{asset.algorithm || "Algorithm not reported"}</p></TableCell><TableCell><p className="font-mono text-xs">{asset.key_size ? `${asset.key_size} bits` : "—"}</p><p className="mt-0.5 text-[11px] text-muted-foreground">{asset.curve || asset.protocol || "No curve/protocol"}</p></TableCell><TableCell><p className="max-w-[220px] truncate font-mono text-[11px]" title={asset.location || undefined}>{truncate(asset.location, 34)}</p></TableCell><TableCell className="text-xs text-muted-foreground">{asset.owner || "Unassigned"}</TableCell><TableCell><StatusBadge status={asset.inventory_status} /></TableCell><TableCell><Button variant="ghost" size="icon-sm" onClick={onOpen} aria-label={`Open details for ${asset.name}`}><ExternalLink className="h-3.5 w-3.5" aria-hidden="true" /></Button></TableCell></TableRow>;
}

function AssetDetail({ asset, loading, error }: { asset?: Asset; loading: boolean; error?: string }) {
  if (loading) return <LoadingState label="Loading asset detail" />;
  if (error) return <ErrorState message={error} />;
  if (!asset) return <EmptyState title="Asset unavailable" description="The asset is not present in the active scope." />;
  const fields: Array<[string, string | null | undefined]> = [["Family", titleCase(asset.family_display || asset.family)], ["Algorithm", asset.algorithm], ["Key size", asset.key_size ? `${asset.key_size} bits` : null], ["Curve", asset.curve], ["Protocol", asset.protocol], ["Library", asset.library], ["Library version", asset.library_version], ["Source type", titleCase(asset.source_type)], ["Owner", asset.owner], ["Inventory state", titleCase(asset.inventory_status_display || asset.inventory_status)], ["Created", formatDate(asset.created_at)]];
  return <div className="space-y-5"><div className="flex items-start justify-between gap-4 border bg-muted/20 p-4"><div className="min-w-0"><p className="text-lg font-semibold">{asset.name}</p><p className="mt-1 font-mono text-xs text-muted-foreground">Asset #{asset.id}</p></div><StatusBadge status={asset.inventory_status} /></div><div><SectionDetail label="Location" value={asset.location || "No location reported"} copyValue={asset.location || undefined} /></div><div className="grid gap-x-6 gap-y-4 sm:grid-cols-2">{fields.map(([label, value]) => <div key={label}><p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{label}</p><p className="mt-1 text-sm">{value || "—"}</p></div>)}</div><p className="border-t pt-4 text-[11px] leading-5 text-muted-foreground">Related findings, assessments, and mitigation references are not included in the current asset serializer. Use the analysis and mitigation pages for those relationships.</p></div>;
}

function SectionDetail({ label, value, copyValue }: { label: string; value: string; copyValue?: string }) {
  return <div className="flex items-start justify-between gap-3"><div className="min-w-0"><p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{label}</p><p className="mt-1 break-all font-mono text-xs">{value}</p></div>{copyValue ? <CopyButton value={copyValue} label="Copy location" /> : null}</div>;
}
