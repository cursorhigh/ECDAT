"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import dynamic from "next/dynamic";
import {
  AlertTriangle,
  Compass,
  Focus,
  LayoutGrid,
  Network,
  RefreshCw,
  Search,
  Share2,
  X
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { EmptyState, ErrorState, LoadingState } from "@/components/feedback/data-state";
import { SectionLabel } from "@/components/data/page-header";
import { Tooltip } from "@/components/ui/tooltip";
import { api } from "@/lib/api/client";
import type { GraphImpact, GraphNodeRow } from "@/lib/api/types";
import { formatNumber, truncate } from "@/lib/utils";
import { useDismissOnOutside } from "@/lib/use-dismiss";
import {
  GROUP_LABEL,
  GROUP_ORDER,
  nodeStyleFor
} from "@/components/data/graph-style";
import type { GraphHandle } from "@/components/data/graph-canvas";

// Cytoscape touches `window` on import, so it must not be in the server bundle.
const GraphCanvas = dynamic(
  () => import("@/components/data/graph-canvas").then((mod) => mod.GraphCanvas),
  { ssr: false, loading: () => <LoadingState label="Preparing the graph" /> }
);

type Layout = "force" | "containment" | "by-type";

const LAYOUTS: { value: Layout; label: string; icon: typeof Network; hint: string }[] = [
  { value: "force", label: "Force", icon: Network, hint: "Spreads the graph so clusters are visible." },
  { value: "containment", label: "Containment", icon: LayoutGrid, hint: "Trees the graph by what contains what." },
  { value: "by-type", label: "By type", icon: Compass, hint: "Primitives in the middle, workloads around them." }
];

const QUESTIONS: { value: string; label: string }[] = [
  { value: "blast-radius", label: "What breaks if this goes away?" },
  { value: "dependents", label: "What depends on this?" },
  { value: "certificates", label: "Which certificates does this use?" }
];

/**
 * The relationship graph for one scan.
 *
 * Everything shown is derived from the unified graph index, so each node is a
 * real discovered entity and every edge carries the evidence that produced it.
 * Nothing is inferred here for display: if an edge is on screen, discovery
 * recorded why.
 */
export function GraphPanel({ scopeKey, ready }: { scopeKey: string; ready: boolean }) {
  const hasSession = ready;
  const [layout, setLayout] = useState<Layout>("force");
  const [hiddenTypes, setHiddenTypes] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<GraphNodeRow | null>(null);
  const [hovered, setHovered] = useState<GraphNodeRow | null>(null);
  const [search, setSearch] = useState("");
  const [showAllRelations, setShowAllRelations] = useState(false);
  const [graphLimit] = useState(600);
  const handleRef = useRef<GraphHandle | null>(null);
  const searchRef = useRef<HTMLInputElement | null>(null);
  const searchWrapRef = useRef<HTMLDivElement | null>(null);

  const graph = useQuery({
    queryKey: ["graph-index", scopeKey, graphLimit],
    queryFn: () => api.graphIndex({ limit: graphLimit }),
    enabled: ready && hasSession
  });

  // One question at a time: the three are different traversals with different
  // meanings, so showing all three at once invites reading one as another.
  const question = "blast-radius";

  // The index is derived data, so rebuilding is always safe to repeat. It is
  // exposed because a scan that finished before the index existed would
  // otherwise have no path to a graph short of re-scanning.
  const rebuild = useMutation({
    mutationFn: api.rebuildGraphIndex,
    onSuccess: () => graph.refetch()
  });

  const impact = useQuery({
    queryKey: ["graph-impact", selected?.id, question],
    queryFn: () => api.graphImpact(selected!.id, question),
    enabled: Boolean(selected)
  });

  const nodes = useMemo(() => graph.data?.nodes || [], [graph.data]);
  const edges = useMemo(() => graph.data?.edges || [], [graph.data]);

  const visibleEdges = useMemo(
    () => (showAllRelations ? edges : edges.filter((edge) => edge.kind !== "co_located" && edge.kind !== "relates_to")),
    [edges, showAllRelations]
  );

  const byType = useMemo(() => {
    const map = new Map<string, number>();
    for (const node of nodes) map.set(node.node_type, (map.get(node.node_type) || 0) + 1);
    return map;
  }, [nodes]);

  const byGroup = useMemo(() => {
    const groups = new Map<string, Array<[string, number]>>();
    for (const [type, count] of byType) {
      const group = nodeStyleFor(type).group;
      if (!groups.has(group)) groups.set(group, []);
      groups.get(group)!.push([type, count]);
    }
    for (const entries of groups.values()) {
      entries.sort((a, b) => b[1] - a[1]);
    }
    return groups;
  }, [byType]);

  const relationCounts = useMemo(() => {
    const map = new Map<string, number>();
    for (const edge of edges) map.set(edge.kind, (map.get(edge.kind) || 0) + 1);
    return map;
  }, [edges]);

  const truncated = nodes.length >= graphLimit;

  const toggleType = useCallback((type: string) => {
    setHiddenTypes((previous) => {
      const next = new Set(previous);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  }, []);

  const matches = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) return [];
    return nodes
      .filter((node) => (node.label || node.key).toLowerCase().includes(needle))
      .slice(0, 8);
  }, [nodes, search]);

  // The node search list is a popover with no outside-click dismissal. Escape is
  // already handled below (it clears the selection and the query), so this only
  // adds the missing case rather than double-firing with that handler.
  useDismissOnOutside({
    active: matches.length > 0,
    ref: searchWrapRef,
    onDismiss: () => setSearch(""),
    closeOnEscape: false
  });

  // Escape clears the selection; "/" focuses search, so a graph can be driven
  // without reaching for the mouse.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      const typing = target && /^(INPUT|TEXTAREA)$/.test(target.tagName);
      if (event.key === "Escape") {
        setSelected(null);
        handleRef.current?.clearFocus();
        setSearch("");
      } else if (event.key === "/" && !typing) {
        event.preventDefault();
        searchRef.current?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  if (graph.isLoading) return <LoadingState label="Reading the relationship graph" />;
  if (graph.isError) {
    const message = graph.error instanceof Error ? graph.error.message : undefined;
    if (message?.includes("No scan is selected")) return null;
    return <ErrorState message={message} onRetry={() => graph.refetch()} />;
  }

  const stats = graph.data?.stats;

  if (!nodes.length) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Relationship graph</CardTitle>
        </CardHeader>
        <CardContent>
          <EmptyState
            title="No relationships recorded for this scan"
            description="The graph is built from the scan's own findings, so it is empty until the scan has something to relate. Run a scan, or import findings from another tool."
          />
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex-row flex-wrap items-start justify-between gap-3">
          <div>
            <CardTitle>Relationship graph</CardTitle>
            <p className="mt-1 text-xs leading-5 text-muted-foreground">
              Every discovered entity in this scan, and the relationships discovery recorded
              between them. Select a node to see what depends on it.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="tnum text-[11px] text-muted-foreground">
              {formatNumber(stats?.nodes || 0)} nodes · {formatNumber(stats?.edges || 0)} edges
            </span>
            <Button variant="ghost" size="sm" onClick={() => handleRef.current?.fit()}>
              <Focus className="h-3.5 w-3.5" aria-hidden="true" />
              Fit
            </Button>
            <Tooltip msg="Recomputes the index from this scan's recorded data. Safe to repeat.">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => rebuild.mutate()}
                disabled={rebuild.isPending}
              >
                <RefreshCw
                  className={`h-3.5 w-3.5 ${rebuild.isPending ? "animate-spin" : ""}`}
                  aria-hidden="true"
                />
                {rebuild.isPending ? "Rebuilding" : "Rebuild"}
              </Button>
            </Tooltip>
          </div>
        </CardHeader>

        <CardContent className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative min-w-[220px] flex-1" ref={searchWrapRef}>
              <Search className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-muted-foreground" aria-hidden="true" />
              <Input
                ref={searchRef}
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Find a node  (press / )"
                className="pl-8"
                aria-label="Find a node in the graph"
              />
              {matches.length ? (
                <ul className="absolute left-0 right-0 top-11 z-30 max-h-56 overflow-y-auto border bg-popover p-1 text-popover-foreground shadow-2xl">
                  {matches.map((node) => {
                    const style = nodeStyleFor(node.node_type);
                    return (
                      <li key={node.id}>
                        <button
                          type="button"
                          className="flex w-full items-center gap-2 px-2 py-1.5 text-left text-xs hover:bg-secondary"
                          onClick={() => {
                            setSelected(node);
                            handleRef.current?.focus(node.id);
                            setSearch("");
                          }}
                        >
                          <span
                            className="inline-block h-2.5 w-2.5 shrink-0"
                            style={{ backgroundColor: style.color }}
                            aria-hidden="true"
                          />
                          <span className="min-w-0 flex-1 truncate">{node.label || node.key}</span>
                          <span className="shrink-0 text-[10px] text-muted-foreground">
                            {style.label}
                          </span>
                        </button>
                      </li>
                    );
                  })}
                </ul>
              ) : null}
            </div>

            <div className="flex items-center gap-1" role="group" aria-label="Graph layout">
              {LAYOUTS.map((option) => (
                <Tooltip key={option.value} msg={option.hint}>
                  <Button
                    variant={layout === option.value ? "secondary" : "ghost"}
                    size="sm"
                    onClick={() => setLayout(option.value)}
                    aria-pressed={layout === option.value}
                  >
                    <option.icon className="h-3.5 w-3.5" aria-hidden="true" />
                    {option.label}
                  </Button>
                </Tooltip>
              ))}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
            {GROUP_ORDER.filter((group) => byGroup.has(group)).map((group) => (
              <div key={group} className="flex items-center gap-1.5">
                <span className="text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground">
                  {GROUP_LABEL[group]}
                </span>
                {byGroup.get(group)!.map(([type, count]) => {
                  const style = nodeStyleFor(type);
                  const hidden = hiddenTypes.has(type);
                  return (
                    <button
                      key={type}
                      type="button"
                      onClick={() => toggleType(type)}
                      aria-pressed={!hidden}
                      className={`inline-flex items-center gap-1.5 border px-1.5 py-0.5 text-[11px] transition-opacity ${
                        hidden ? "border-border text-muted-foreground opacity-40" : "border-border text-foreground"
                      }`}
                    >
                      <span
                        className="inline-block h-2 w-2"
                        style={{ backgroundColor: style.color }}
                        aria-hidden="true"
                      />
                      {style.label}
                      <span className="tnum text-muted-foreground">{count}</span>
                    </button>
                  );
                })}
              </div>
            ))}

            {relationCounts.has("co_located") || relationCounts.has("relates_to") ? (
              <Button
                variant={showAllRelations ? "secondary" : "ghost"}
                size="sm"
                onClick={() => setShowAllRelations((value) => !value)}
                aria-pressed={showAllRelations}
                className="ml-auto"
              >
                <Share2 className="h-3.5 w-3.5" aria-hidden="true" />
                {showAllRelations ? "Hiding weak links" : "Show weak links"}
              </Button>
            ) : null}
          </div>

          {truncated ? (
            <p className="flex items-start gap-2 border border-amber-500/40 bg-amber-500/5 px-2.5 py-2 text-[11px] leading-4 text-amber-700 dark:text-amber-400">
              <AlertTriangle className="mt-px h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              <span>
                Showing the first {formatNumber(graphLimit)} of this scan&apos;s nodes. A larger scan
                is drawn in part, so what is on screen is not the whole relationship set.
              </span>
            </p>
          ) : null}
        </CardContent>
      </Card>

      {/* `items-start` is load-bearing. A grid row stretches to its tallest
          column by default, so selecting a node with a long impact list grew the
          row and the graph card grew with it -- the canvas kept its 560px but
          the frame around it visibly resized. Pinning both columns to the top
          decouples them; the detail column scrolls on its own instead. */}
      <div className="grid items-start gap-4 lg:grid-cols-[1.6fr_1fr]">
        <Card className="overflow-hidden">
          <CardContent className="p-0">
            <div className="h-[560px] w-full">
              <GraphCanvas
                nodes={nodes}
                edges={visibleEdges}
                onSelect={setSelected}
                onHover={setHovered}
                hiddenTypes={hiddenTypes}
                handleRef={handleRef}
                layout={layout}
              />
            </div>
          </CardContent>
        </Card>

        <div className="scrollbar-thin space-y-4 lg:max-h-[620px] lg:overflow-y-auto lg:pr-1">
          {hovered && !selected ? (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <span
                    className="inline-block h-2.5 w-2.5"
                    style={{ backgroundColor: nodeStyleFor(hovered.node_type).color }}
                    aria-hidden="true"
                  />
                  {truncate(hovered.label || hovered.key, 44)}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-xs">
                <p className="text-muted-foreground">
                  {nodeStyleFor(hovered.node_type).label} · select to inspect its relationships
                </p>
                <DetailRows node={hovered} />
              </CardContent>
            </Card>
          ) : null}

          {selected ? (
            <NodeDetail
              node={selected}
              impact={impact.data}
              loading={impact.isLoading}
              onClose={() => {
                setSelected(null);
                handleRef.current?.clearFocus();
              }}
            />
          ) : (
            <Card>
              <CardHeader>
                <CardTitle>Impact</CardTitle>
              </CardHeader>
              <CardContent>
                <EmptyState
                  title="Select a node"
                  description="Click any node to see what discovery recorded about it, and what would be affected if it were removed."
                />
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

function NodeDetail({
  node,
  impact,
  loading,
  onClose
}: {
  node: GraphNodeRow;
  impact?: GraphImpact;
  loading: boolean;
  onClose: () => void;
}) {
  const style = nodeStyleFor(node.node_type);
  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between gap-3">
        <div className="min-w-0">
          <CardTitle className="flex items-center gap-2">
            <span
              className="inline-block h-2.5 w-2.5 shrink-0"
              style={{ backgroundColor: style.color }}
              aria-hidden="true"
            />
            <span className="truncate">{node.label || node.key}</span>
          </CardTitle>
          <p className="mt-1 text-[11px] text-muted-foreground">{style.label}</p>
        </div>
        <Button variant="ghost" size="icon" onClick={onClose} aria-label="Clear selection">
          <X className="h-3.5 w-3.5" aria-hidden="true" />
        </Button>
      </CardHeader>
      <CardContent className="space-y-4">
        <DetailRows node={node} />

        <div className="space-y-2 border-t pt-3">
          <SectionLabel>What is affected</SectionLabel>
          {loading ? (
            <p className="text-[11px] text-muted-foreground">Walking the relationships…</p>
          ) : !impact || !impact.count ? (
            <p className="text-[11px] leading-4 text-muted-foreground">
              Nothing else in this scan is recorded as depending on it. That is what the graph
              says, not a claim that it has no impact.
            </p>
          ) : (
            <>
              <p className="text-[11px] text-muted-foreground">
                {formatNumber(impact.count)} node{impact.count === 1 ? "" : "s"} reachable from here
                {impact.truncated ? " (list truncated)" : ""}.
              </p>
              <ul className="space-y-1">
                {(impact.affected || []).slice(0, 10).map((row) => (
                  <li key={row.id} className="flex items-center gap-2 text-[11px]">
                    <span
                      className="inline-block h-2 w-2 shrink-0"
                      style={{ backgroundColor: nodeStyleFor(row.node_type).color }}
                      aria-hidden="true"
                    />
                    <span className="min-w-0 flex-1 truncate">{row.label || row.key}</span>
                    <span className="shrink-0 text-muted-foreground">
                      {nodeStyleFor(row.node_type).label}
                    </span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function DetailRows({ node }: { node: GraphNodeRow }) {
  const detail = (node.detail || {}) as Record<string, unknown>;
  const rows: Array<[string, unknown]> = [
    ["Family", node.family],
    ["Algorithm", node.algorithm || detail.algorithm],
    ["Key size", detail.key_size],
    ["Curve", detail.curve],
    ["Protocol", detail.protocol],
    ["Library", detail.library],
    ["Owner", detail.owner],
    ["Source", node.source_type],
    ["Location", detail.location || detail.path || detail.root || node.location]
  ];
  const present = rows.filter(([, value]) => value !== undefined && value !== null && value !== "");
  if (!present.length) {
    return <p className="text-[11px] text-muted-foreground">No further detail was recorded.</p>;
  }
  return (
    <dl className="space-y-1 text-[11px]">
      {present.map(([label, value]) => (
        <div key={label} className="flex gap-2">
          <dt className="w-20 shrink-0 text-muted-foreground">{label}</dt>
          <dd className="min-w-0 flex-1 break-words font-mono">{String(value)}</dd>
        </div>
      ))}
    </dl>
  );
}
