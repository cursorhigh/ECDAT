import { cn } from "@/lib/utils";

export function PageHeader({ eyebrow, title, description, actions, className, compact = false }: { eyebrow?: string; title: string; description?: string; actions?: React.ReactNode; className?: string; compact?: boolean }) {
  return (
    <div className={cn("flex border-b", compact ? "flex-col gap-3 pb-4 sm:flex-row sm:items-center sm:justify-between" : "flex-col gap-4 pb-6 sm:flex-row sm:items-end sm:justify-between", className)}>
      <div className={cn("min-w-0", compact && "flex min-w-0 flex-1 items-center gap-4")}>
        <div className={cn("min-w-0", compact && "shrink-0")}>
          {eyebrow ? <p className={cn("mb-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-primary", compact && "mb-1 text-[10px]")}>{eyebrow}</p> : null}
          <h1 className={cn("text-2xl font-semibold tracking-tight sm:text-3xl", compact && "text-xl sm:text-2xl")}>{title}</h1>
        </div>
        {description ? <p className={cn("mt-2 max-w-2xl text-sm leading-6 text-muted-foreground", compact && "mt-0 hidden max-w-xl border-l pl-4 text-xs leading-5 lg:block")}>{description}</p> : null}
      </div>
      {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function SectionLabel({ children, className }: { children: React.ReactNode; className?: string }) {
  return <p className={cn("text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground", className)}>{children}</p>;
}
