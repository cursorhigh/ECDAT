import Link from "next/link";
import { ArrowUpRight, type LucideIcon } from "lucide-react";
import { Card } from "@/components/ui/card";
import { cn, formatNumber } from "@/lib/utils";

export function MetricCard({ label, value, detail, icon: Icon, tone = "default", href }: { label: string; value: number | string | null | undefined; detail?: string; icon?: LucideIcon; tone?: "default" | "accent" | "warning" | "danger"; href?: string }) {
  const content = (
    <Card className={cn("group relative h-full overflow-hidden p-5", tone === "accent" && "border-primary/40", tone === "warning" && "border-warning/35", tone === "danger" && "border-destructive/35")}>
      <div className="flex items-start justify-between gap-3">
        <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{label}</p>
        {Icon ? <Icon className={cn("h-4 w-4", tone === "danger" ? "text-destructive" : tone === "warning" ? "text-warning" : tone === "accent" ? "text-primary" : "text-muted-foreground")} aria-hidden="true" /> : null}
      </div>
      <p className="tnum mt-4 text-3xl font-semibold tracking-tight">{typeof value === "number" ? formatNumber(value) : value || "—"}</p>
      {detail ? <p className="mt-1 text-xs text-muted-foreground">{detail}</p> : null}
      {href ? <ArrowUpRight className="absolute bottom-4 right-4 h-4 w-4 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" aria-hidden="true" /> : null}
    </Card>
  );
  return href ? <Link href={href} className="block rounded-none">{content}</Link> : content;
}
