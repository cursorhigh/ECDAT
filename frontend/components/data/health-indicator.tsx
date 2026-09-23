import { Activity, Database, Server, Wifi, WifiOff } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { useSession } from "@/lib/session-context";

export function HealthIndicator() {
  const { scopeKey } = useSession();
  const query = useQuery({ queryKey: ["health", scopeKey], queryFn: api.health, refetchInterval: 30000, staleTime: 10000 });
  const isHealthy = query.data?.status === "ok";
  return (
    <div className="flex items-center gap-2" title={query.data ? `${query.data.service} · ${query.data.active_mode} mode` : "Service health unavailable"}>
      {isHealthy ? <Wifi className="h-3.5 w-3.5 text-success" aria-hidden="true" /> : <WifiOff className="h-3.5 w-3.5 text-destructive" aria-hidden="true" />}
      <span className="hidden text-xs text-muted-foreground sm:inline">{isHealthy ? "Service online" : query.isError ? "Service offline" : "Checking service"}</span>
    </div>
  );
}

export function HealthCards() {
  const query = useQuery({ queryKey: ["health", "settings"], queryFn: api.health, refetchInterval: 30000 });
  if (query.isLoading) return <div className="h-28 animate-pulse bg-muted" />;
  const health = query.data;
  return (
    <div className="grid gap-3 sm:grid-cols-3">
      <Card><CardHeader className="pb-3"><CardTitle className="flex items-center gap-2"><Server className="h-4 w-4" aria-hidden="true" />Platform service</CardTitle></CardHeader><CardContent><Badge variant={health?.status === "ok" ? "success" : "danger"}>{health?.status || "Unavailable"}</Badge><p className="mt-2 text-xs text-muted-foreground">{health?.service || "Status unavailable"}</p></CardContent></Card>
      <Card><CardHeader className="pb-3"><CardTitle className="flex items-center gap-2"><Database className="h-4 w-4" aria-hidden="true" />Data boundary</CardTitle></CardHeader><CardContent><p className="font-mono text-sm">{health?.active_db || "Unavailable"}</p><p className="mt-2 text-xs text-muted-foreground">Mode: {health?.active_mode || "Unknown"}</p></CardContent></Card>
      <Card><CardHeader className="pb-3"><CardTitle className="flex items-center gap-2"><Activity className="h-4 w-4" aria-hidden="true" />Worker status</CardTitle></CardHeader><CardContent><Badge variant="muted">Unavailable</Badge><p className="mt-2 text-xs text-muted-foreground">Worker status is not currently available.</p></CardContent></Card>
    </div>
  );
}
