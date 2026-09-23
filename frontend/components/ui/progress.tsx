import { cn } from "@/lib/utils";

export function Progress({ value, className, indicatorClassName }: { value?: number; className?: string; indicatorClassName?: string }) {
  const safeValue = Math.max(0, Math.min(100, Number(value) || 0));
  return (
    <div className={cn("h-1.5 w-full overflow-hidden bg-secondary", className)} role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={safeValue}>
      <div className={cn("h-full bg-primary transition-[width] duration-500", indicatorClassName)} style={{ width: `${safeValue}%` }} />
    </div>
  );
}
