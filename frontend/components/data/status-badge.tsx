import { CircleAlert, CircleCheck, CircleDashed, CircleDot, Clock3, OctagonX, ShieldCheck } from "lucide-react";
import { Badge, type BadgeProps } from "@/components/ui/badge";
import { cn, titleCase } from "@/lib/utils";

const statusMap: Record<string, { label: string; variant: BadgeProps["variant"]; icon: typeof CircleCheck }> = {
  completed: { label: "Completed", variant: "success", icon: CircleCheck },
  complete: { label: "Complete", variant: "success", icon: CircleCheck },
  passed: { label: "Passed", variant: "success", icon: CircleCheck },
  queued: { label: "Queued", variant: "info", icon: Clock3 },
  pending: { label: "Pending", variant: "info", icon: Clock3 },
  running: { label: "Running", variant: "info", icon: CircleDot },
  generating: { label: "Generating", variant: "info", icon: CircleDot },
  awaiting_context: { label: "Awaiting context", variant: "warning", icon: Clock3 },
  failed: { label: "Failed", variant: "danger", icon: OctagonX },
  cancelled: { label: "Cancelled", variant: "muted", icon: CircleAlert },
  canceled: { label: "Cancelled", variant: "muted", icon: CircleAlert },
  active: { label: "Active", variant: "success", icon: ShieldCheck },
  dormant: { label: "Dormant", variant: "muted", icon: CircleDashed },
  needs_review: { label: "Needs review", variant: "warning", icon: CircleAlert }
};

export function StatusBadge({ status, label, className }: { status?: string | null; label?: string; className?: string }) {
  const key = (status || "unknown").toLowerCase();
  const config = statusMap[key] || { label: titleCase(status || "Unknown"), variant: "muted" as const, icon: CircleDashed };
  const Icon = config.icon;
  return <Badge variant={config.variant} className={cn("normal-case tracking-normal", className)}><Icon className="h-3 w-3" aria-hidden="true" />{label || config.label}</Badge>;
}

export function riskBadge(label?: unknown) {
  const value = String(label || "unknown").toLowerCase();
  if (["vulnerable", "critical", "urgent", "high"].includes(value)) return <Badge variant="danger" className="normal-case tracking-normal">{titleCase(label)}</Badge>;
  if (["weak", "medium", "moderate"].includes(value)) return <Badge variant="warning" className="normal-case tracking-normal">{titleCase(label)}</Badge>;
  if (["pqc", "pqc-ready", "low", "ready"].includes(value)) return <Badge variant="success" className="normal-case tracking-normal">{titleCase(label)}</Badge>;
  return <Badge variant="muted" className="normal-case tracking-normal">{titleCase(label)}</Badge>;
}
