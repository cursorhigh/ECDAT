import { cn } from "@/lib/utils";

export function PageHeader({ eyebrow, title, description, actions, className }: { eyebrow?: string; title: string; description?: string; actions?: React.ReactNode; className?: string }) {
  return (
    <div className={cn("flex flex-col gap-4 border-b pb-6 sm:flex-row sm:items-end sm:justify-between", className)}>
      <div className="min-w-0">
        {eyebrow ? <p className="mb-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-primary">{eyebrow}</p> : null}
        <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">{title}</h1>
        {description ? <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">{description}</p> : null}
      </div>
      {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function SectionLabel({ children, className }: { children: React.ReactNode; className?: string }) {
  return <p className={cn("text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground", className)}>{children}</p>;
}
