import { Activity, Database, Server, Wifi, WifiOff } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { NavTooltip } from "@/components/ui/nav-tooltip";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { useSession } from "@/lib/session-context";

export function HealthIndicator() {
  const { scopeKey } = useSession();
  const query = useQuery({ queryKey: ["health", scopeKey], queryFn: api.health, refetchInterval: 30000, staleTime: 10000 });
  const isHealthy = query.data?.status === "ok";
    return (
      <NavTooltip
        title={isHealthy ? "Service online" : query.isError ? "Service offline" : "Checking service"}
        description={
          query.data
            ? `${query.data.service} · database ${query.data.active_db}. Re-checked every 30 seconds.`
            : "The backend did not answer the health check. API calls will fail until it recovers."
        }
        tone={isHealthy ? "default" : "destructive"}
      >
        <div className="flex items-center gap-2">
          {isHealthy ? <Wifi className="h-3.5 w-3.5 text-success" aria-hidden="true" /> : <WifiOff className="h-3.5 w-3.5 text-destructive" aria-hidden="true" />}
          <span className="hidden text-xs text-muted-foreground sm:inline">{isHealthy ? "Service online" : query.isError ? "Service offline" : "Checking service"}</span>
        </div>
      </NavTooltip>
    );
  }

export function HealthCards() {
  const query = useQuery({ queryKey: ["health", "settings"], queryFn: api.health, refetchInterval: 30000 });
  if (query.isLoading) return <div className="h-24 animate-pulse bg-muted" />;
  const health = query.data;
  const worker = health?.worker;
  const dbUp = health?.database_up ?? health?.status === "ok";

  // A backend too old to report the worker must be distinguishable from a
  // worker that is genuinely down, so "not reported" never borrows the
  // offline styling.
  const workerBadge = !worker
    ? { label: "Not reported", variant: "muted" as const }
    : worker.mode === "inline"
      ? { label: "In-process", variant: "muted" as const }
      : worker.running
        ? { label: worker.pending > 0 ? `Working · ${worker.pending}` : "Idle", variant: "success" as const }
        : { label: "Not running", variant: "danger" as const };

  return (
    <div className="grid gap-3 sm:grid-cols-3">
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center justify-between gap-2 text-sm">
            <span className="flex items-center gap-2">
              <Server className="h-4 w-4 text-primary" aria-hidden="true" />
              Service
            </span>
            <Badge variant={dbUp ? "success" : "danger"}>{dbUp ? "Online" : "Degraded"}</Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="font-mono text-[11px] text-muted-foreground">{health?.service || "unreachable"}</p>
          <p className="mt-1 text-[11px] text-muted-foreground">
            {dbUp ? "API and database responding." : "The database did not answer the health check."}
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center justify-between gap-2 text-sm">
            <span className="flex items-center gap-2">
              <Database className="h-4 w-4 text-primary" aria-hidden="true" />
              Data
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="font-mono text-[11px] text-muted-foreground">{health?.active_db || "unknown"}</p>
          <p className="mt-1 text-[11px] text-muted-foreground">
            Reads and writes go to this database.
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center justify-between gap-2 text-sm">
            <span className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-primary" aria-hidden="true" />
              Worker
            </span>
            <Badge variant={workerBadge.variant}>{workerBadge.label}</Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-[11px] leading-4 text-muted-foreground">
            {worker?.detail || "This backend does not report worker state."}
          </p>
          {worker && worker.mode === "queue" ? (
            <p className="mt-1 font-mono text-[10px] text-muted-foreground">
              {worker.pending} queued · {worker.scheduled} scheduled
              {worker.workers ? ` · ${worker.workers} threads` : ""}
            </p>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}
