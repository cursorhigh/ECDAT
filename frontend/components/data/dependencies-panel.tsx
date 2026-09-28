"use client";

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { AlertTriangle } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { RefreshButton } from "@/components/ui/refresh-button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState, ErrorState, LoadingState } from "@/components/feedback/data-state";
import { api, isNoScanSelected } from "@/lib/api/client";
import { formatNumber, titleCase } from "@/lib/utils";

/**
 * The dependency graph, read as declared packages rather than as findings.
 *
 * It moved here from the scans page: dependencies describe what a scan brought
 * back about the estate, not how the scan was run, so they belong with the
 * discovered assets rather than next to the start button.
 */
export function DependenciesPanel({ scopeKey, ready }: { scopeKey: string; ready: boolean }) {
  const [cryptoOnly, setCryptoOnly] = useState(false);
  const hasSession = ready;

  const dependencies = useQuery({
    queryKey: ["dependencies", scopeKey, cryptoOnly],
    queryFn: () => api.dependencies(cryptoOnly ? { crypto_only: 1 } : undefined),
    enabled: ready && hasSession
  });
  const depGraph = useQuery({
    queryKey: ["dependency-graph", scopeKey],
    queryFn: () => api.dependencyGraph(),
    enabled: ready && hasSession
  });

  // Memoised so it is a stable dependency: a fresh array on every render would
  // make the `keyServices` memo below recompute constantly.
  const dependencyRows = useMemo(() => dependencies.data?.results || [], [dependencies.data]);
  const dependencyTotal = dependencies.data?.count || 0;
  const graph = depGraph.data;

  // Reverse index, so each package can show what pulls it in and what it backs.
  const dependentsByNode = useMemo(() => {
    const map = new Map<string, number>();
    for (const edge of graph?.dependency_edges || []) {
      if (edge.kind === "depends_on") {
        map.set(edge.to, (map.get(edge.to) || 0) + 1);
      }
    }
    return map;
  }, [graph]);
  const providesByNode = useMemo(() => {
    const map = new Map<string, number>();
    for (const edge of graph?.dependency_edges || []) {
      if (edge.kind === "provides") {
        map.set(edge.from, (map.get(edge.from) || 0) + 1);
      }
    }
    return map;
  }, [graph]);
  const nodeIdByPackage = useMemo(() => {
    const map = new Map<string, string>();
    for (const node of graph?.dependency_nodes || []) {
      map.set(`${node.ecosystem}:${node.package}`, node.id);
    }
    return map;
  }, [graph]);
  const transitiveCount = useMemo(
    () => (graph?.dependency_edges || []).filter((edge) => edge.kind === "depends_on").length,
    [graph]
  );
  const providesCount = providesByNode.size;
  const keyServices = useMemo(
    () =>
      Array.from(
        new Set(
          dependencyRows
            .map((row) => row.key_service)
            .filter((service): service is string => Boolean(service))
        )
      ),
    [dependencyRows]
  );

  return (
    <>
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
                <Link href="/scans" className={buttonVariants({ variant: "outline", size: "sm" })}>
                  Start a discovery scan
                </Link>
              )}
            />
          </div>
        )}
      </CardContent>
    </Card>
    </>
  );
}

function DependencyImpact({ dependents, provides }: { dependents: number; provides: number }) {
  if (!dependents && !provides) {
    return <span className="text-muted-foreground">Standalone</span>;
  }
  return (
    <span className="inline-flex items-center gap-2">
      {dependents ? <span>{dependents} dependent{dependents === 1 ? "" : "s"}</span> : null}
      {provides ? <span>{provides} asset{provides === 1 ? "" : "s"}</span> : null}
    </span>
  );
}

function RelevanceBadge({ relevance }: { relevance: string }) {
  if (!relevance) return <span className="text-muted-foreground">-</span>;
  return (
    <Badge variant={relevance === "core" ? "outline" : "muted"} className="normal-case tracking-normal">
      {titleCase(relevance)}
    </Badge>
  );
}
