"use client";

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Boxes, GitBranch, Loader2, Network, Radar, RefreshCw, Share2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Tooltip } from "@/components/ui/tooltip";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState, ErrorState, LoadingState } from "@/components/feedback/data-state";
import { SectionLabel } from "@/components/data/page-header";
import { useToast } from "@/components/feedback/toast";
import { api } from "@/lib/api/client";
import type { GraphImpact, GraphNodeRow } from "@/lib/api/types";
import { cn, formatNumber, titleCase } from "@/lib/utils";

/**
 * The unified relationship graph.
 *
 * The point of this view is not a pretty hairball; it is answering three
 * questions that no single table could answer before: what depends on this
 * library, which certificates does this application use, and what breaks if
 * this key goes away.
 */

const NODE_TONES: Record<string, string> = {
  application: "border-primary/40 bg-primary/10 text-primary",
  repository: "border-primary/30 bg-primary/5 text-primary",
  container: "border-info/40 bg-info/10 text-info",
  file: "border-border bg-muted/40 text-muted-foreground",
  api: "border-info/40 bg-info/10 text-info",
  library: "border-warning/40 bg-warning/10 text-warning",
  dependency: "border-warning/40 bg-warning/10 text-warning",
  algorithm: "border-destructive/40 bg-destructive/10 text-destructive",
  key: "border-destructive/40 bg-destructive/10 text-destructive",
  certificate: "border-success/40 bg-success/10 text-success",
  protocol: "border-info/40 bg-info/10 text-info",
  endpoint: "border-info/40 bg-info/10 text-info",
  infrastructure: "border-border bg-muted/40 text-muted-foreground",
};

const QUESTIONS: Array<{ value: string; label: string; hint: string }> = [
  { value: "dependents", label: "What depends on this?", hint: "Walks depends_on edges backwards." },
  { value: "certificates", label: "Which certificates does it use?", hint: "Follows contains and uses edges." },
  { value: "blast-radius", label: "What breaks if this goes away?", hint: "Walks both directions." },
];

export function GraphPanel({ scopeKey, ready }: { scopeKey: string; ready: boolean }) {
  const { pushToast } = useToast();
  const queryClient = useQueryClient();
  const [typeFilter, setTypeFilter] = useState("");
  const [selected, setSelected] = useState<GraphNodeRow | null>(null);
  const [question, setQuestion] = useState("blast-radius");

  const graph = useQuery({
    queryKey: ["graph-index", scopeKey, typeFilter],
    queryFn: () =>
      api.graphIndex(typeFilter ? { node_type: typeFilter, limit: 500 } : { limit: 500 }),
    enabled: ready,
  });

  const impact = useQuery({
    queryKey: ["graph-impact", scopeKey, selected?.id, question],
    queryFn: () => api.graphImpact(selected!.id, question),
    enabled: ready && Boolean(selected),
  });

  const rebuild = useMutation({
    mutationFn: api.rebuildGraphIndex,
    onSuccess: async (result) => {
      pushToast(
        `Graph rebuilt: ${formatNumber(result.nodes_created + result.nodes_reused)} nodes, ` +
          `${formatNumber(result.edges_created)} new edges.`,
        "success",
      );
      if (result.unmapped_asset_types.length) {
        // Surfaced, not swallowed: a new asset type with no node mapping would
        // otherwise be invisible everywhere.
        pushToast(
          `Unmapped asset types: ${result.unmapped_asset_types.join(", ")}`,
          "info",
        );
      }
      await queryClient.invalidateQueries({ queryKey: ["graph-index"] });
    },
    onError: (error) =>
      pushToast(error instanceof Error ? error.message : "The graph could not be rebuilt.", "error"),
  });

  const nodes = graph.data?.nodes || [];
  const stats = graph.data?.stats;
  const nodeTypes = useMemo(
    () => Object.entries(stats?.nodes_by_type || {}).sort((a, b) => b[1] - a[1]),
    [stats],
  );

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex-row items-start justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Network className="h-4 w-4 text-primary" aria-hidden="true" />
              Relationship graph
            </CardTitle>
            <p className="mt-1 text-xs leading-5 text-muted-foreground">
              One graph across repositories, applications, files, libraries, algorithms, keys,
              certificates and endpoints. Every link records why it exists.
            </p>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => rebuild.mutate()}
            disabled={rebuild.isPending}
          >
            {rebuild.isPending ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
            ) : (
              <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
            )}
            Rebuild
          </Button>
        </CardHeader>
        {graph.isLoading ? (
          <CardContent className="p-5">
            <LoadingState label="Loading the relationship graph" />
          </CardContent>
        ) : graph.isError ? (
          <CardContent className="p-5">
            <ErrorState
              message={graph.error instanceof Error ? graph.error.message : undefined}
              onRetry={() => void graph.refetch()}
            />
          </CardContent>
        ) : !stats?.nodes ? (
          <CardContent className="p-5">
            <EmptyState
              title="The graph is empty"
              description="Run a discovery scan. The graph is built from what discovery records and can be rebuilt at any time."
            />
          </CardContent>
        ) : (
          <CardContent className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-3">
              <Stat label="Nodes" value={stats.nodes} icon={Boxes} />
              <Stat label="Relationships" value={stats.edges} icon={GitBranch} />
              <Stat label="Entity types" value={nodeTypes.length} icon={Network} />
            </div>

            {nodeTypes.length ? (
              <div>
                <SectionLabel>Entities</SectionLabel>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  <TypeChip
                    label="All"
                    count={stats.nodes}
                    active={typeFilter === ""}
                    onClick={() => setTypeFilter("")}
                  />
                  {nodeTypes.map(([type, count]) => (
                    <TypeChip
                      key={type}
                      label={titleCase(type)}
                      count={count}
                      active={typeFilter === type}
                      tone={NODE_TONES[type]}
                      onClick={() => setTypeFilter(typeFilter === type ? "" : type)}
                    />
                  ))}
                </div>
              </div>
            ) : null}

            <p className="text-[11px] leading-4 text-muted-foreground">
              Select a node to see what depends on it, what it uses, and what it would break.
            </p>
          </CardContent>
        )}
      </Card>

      {stats?.nodes ? (
        <div className="grid gap-4 xl:grid-cols-[1.1fr_0.9fr]">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">
                {typeFilter ? `${titleCase(typeFilter)} nodes` : "All nodes"}
                <span className="ml-2 font-mono text-[11px] font-normal text-muted-foreground">
                  {formatNumber(nodes.length)}
                </span>
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              {nodes.length ? (
                <div className="max-h-[520px] overflow-y-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Type</TableHead>
                        <TableHead>Node</TableHead>
                        <TableHead>Detail</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {nodes.map((node) => (
                        <TableRow
                          key={node.id}
                          onClick={() => setSelected(node)}
                          className={cn(
                            "cursor-pointer",
                            selected?.id === node.id && "bg-primary/5",
                          )}
                        >
                          <TableCell>
                            <span
                              className={cn(
                                "inline-block whitespace-nowrap border px-1.5 py-0.5 text-[10px] uppercase tracking-[0.08em]",
                                NODE_TONES[node.node_type] || "border-border text-muted-foreground",
                              )}
                            >
                              {node.node_type_display}
                            </span>
                          </TableCell>
                          <TableCell className="min-w-0">
                            <p className="truncate text-xs font-medium" title={node.label}>
                              {node.label}
                            </p>
                            {node.location ? (
                              <p
                                className="truncate font-mono text-[11px] text-muted-foreground"
                                title={node.location}
                              >
                                {node.location}
                              </p>
                            ) : null}
                          </TableCell>
                          <TableCell className="text-[11px] text-muted-foreground">
                            {node.algorithm || node.family || "—"}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              ) : (
                <div className="p-5">
                  <EmptyState
                    title="No nodes of this type"
                    description="Choose a different entity type, or clear the filter."
                  />
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Impact</CardTitle>
              {selected ? (
                <p className="mt-1 text-[11px] text-muted-foreground">
                  Asked about{" "}
                  <span className="text-foreground">{selected.label}</span> (
                  {selected.node_type_display})
                </p>
              ) : null}
            </CardHeader>
            <CardContent className="space-y-3">
              {!selected ? (
                <EmptyState
                  title="Nothing selected"
                  description="Pick a node from the list to trace its relationships."
                />
              ) : (
                <>
                  <div className="flex flex-wrap gap-1.5">
                    {QUESTIONS.map((item) => (
                      <Tooltip key={item.value} msg={item.hint} placement="top" offset={8}>
                        <button
                          type="button"
                          onClick={() => setQuestion(item.value)}
                          aria-pressed={question === item.value}
                          className={cn(
                            "border px-2.5 py-1 text-[11px] transition-colors",
                            question === item.value
                              ? "border-primary bg-primary/10 text-primary"
                              : "border-border text-muted-foreground hover:bg-muted",
                          )}
                        >
                          {item.label}
                        </button>
                      </Tooltip>
                    ))}
                  </div>

                  <ImpactResult impact={impact.data} loading={impact.isFetching} />
                </>
              )}
            </CardContent>
          </Card>
        </div>
      ) : null}
    </div>
  );
}

function ImpactResult({ impact, loading }: { impact?: GraphImpact; loading: boolean }) {
  if (loading) return <LoadingState label="Tracing relationships" />;
  if (!impact) return null;

  if (impact.truncated) {
    return (
      <div className="border border-warning/40 bg-warning/5 p-3 text-[11px] leading-4 text-warning">
        This answer was capped to keep the query bounded. Narrow the starting node for the full
        picture.
      </div>
    );
  }

  if (!impact.count) {
    return (
      <p className="text-xs text-muted-foreground">
        Nothing is connected to this node by that relationship.
      </p>
    );
  }

  if (impact.by_type) {
    return (
      <div className="space-y-3">
        <div className="flex flex-wrap gap-1.5">
          {Object.entries(impact.by_type).map(([type, count]) => (
            <span
              key={type}
              className={cn(
                "border px-2 py-0.5 text-[11px]",
                NODE_TONES[type] || "border-border text-muted-foreground",
              )}
            >
              {titleCase(type)} <span className="tnum">{formatNumber(count)}</span>
            </span>
          ))}
        </div>
        <ul className="space-y-1">
          {(impact.affected || []).slice(0, 40).map((node) => (
            <li key={node.id} className="flex items-center gap-2 border-b pb-1 last:border-0">
              <span className="shrink-0 text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
                {node.node_type_display}
              </span>
              <span className="truncate text-xs" title={node.location || node.label}>
                {node.label}
              </span>
            </li>
          ))}
        </ul>
        {(impact.affected?.length || 0) > 40 ? (
          <p className="text-[11px] text-muted-foreground">
            Showing the first 40 of {formatNumber(impact.affected?.length || 0)}.
          </p>
        ) : null}
      </div>
    );
  }

  return (
    <ul className="space-y-2">
      {impact.paths.slice(0, 40).map((entry, index) => (
        <li key={`${index}-${entry.length}`} className="border p-2">
          <div className="flex flex-wrap items-center gap-1 text-[11px]">
            {entry.path.map((hop, hopIndex) => (
              <span key={`${hop.node.id}-${hopIndex}`} className="flex items-center gap-1">
                {hopIndex > 0 ? (
                  <span className="text-muted-foreground">
                    <Share2 className="h-3 w-3" aria-hidden="true" />
                  </span>
                ) : null}
                <span
                  className={cn(
                    "border px-1.5 py-0.5",
                    NODE_TONES[hop.node.node_type] || "border-border text-muted-foreground",
                  )}
                  title={hop.why?.why ? String(hop.why.why) : undefined}
                >
                  {hop.node.label}
                </span>
              </span>
            ))}
          </div>
        </li>
      ))}
      {impact.paths.length > 40 ? (
        <p className="text-[11px] text-muted-foreground">
          Showing the first 40 of {formatNumber(impact.paths.length)} paths.
        </p>
      ) : null}
    </ul>
  );
}

function Stat({ label, value, icon: Icon }: { label: string; value: number; icon: typeof Boxes }) {
  return (
    <div className="border p-3">
      <div className="flex items-center justify-between">
        <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
          {label}
        </p>
        <Icon className="h-3.5 w-3.5 text-muted-foreground" aria-hidden="true" />
      </div>
      <p className="tnum mt-2 text-2xl font-semibold">{formatNumber(value)}</p>
    </div>
  );
}

function TypeChip({
  label,
  count,
  active,
  tone,
  onClick,
}: {
  label: string;
  count: number;
  active: boolean;
  tone?: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        "border px-2 py-0.5 text-[11px] transition-colors",
        active ? "border-primary bg-primary/10 text-primary" : tone || "border-border text-muted-foreground hover:bg-muted",
      )}
    >
      {label} <span className="tnum">{formatNumber(count)}</span>
    </button>
  );
}
