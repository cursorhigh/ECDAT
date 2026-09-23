import { cn } from "@/lib/utils";

export function Tabs({ value, onValueChange, items }: { value: string; onValueChange: (value: string) => void; items: Array<{ value: string; label: string; count?: number }> }) {
  return (
    <div className="flex items-center gap-1 border-b" role="tablist">
      {items.map((item) => (
        <button key={item.value} type="button" role="tab" aria-selected={value === item.value} onClick={() => onValueChange(item.value)} className={cn("relative -mb-px flex h-10 items-center gap-2 border-b-2 px-3 text-sm font-medium transition-colors", value === item.value ? "border-primary text-foreground" : "border-transparent text-muted-foreground hover:text-foreground")}>
          {item.label}
          {typeof item.count === "number" ? <span className="tnum text-[11px] text-muted-foreground">{item.count}</span> : null}
        </button>
      ))}
    </div>
  );
}
