"use client";

import { useEffect } from "react";
import { X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export function Dialog({ open, onOpenChange, title, description, children, footer, className, variant = "default" }: { open: boolean; onOpenChange: (open: boolean) => void; title: string; description?: string; children: React.ReactNode; footer?: React.ReactNode; className?: string; variant?: "default" | "dark" }) {
  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onOpenChange(false);
    };
    document.addEventListener("keydown", onKeyDown);
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.body.style.overflow = previous;
    };
  }, [onOpenChange, open]);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-[70] flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="dialog-title">
      <button type="button" className="dialog-overlay absolute inset-0 cursor-default bg-background/80 backdrop-blur-[2px]" onClick={() => onOpenChange(false)} aria-label="Close dialog" />
      <div className={cn("dialog-panel relative z-10 w-full max-w-lg border shadow-2xl", variant === "dark" ? "bg-black text-white" : "bg-card", className)}>
        <div className="flex items-start justify-between border-b px-5 py-4">
          <div>
            <h2 id="dialog-title" className={cn("text-base font-semibold", variant === "dark" && "text-white")}>{title}</h2>
            {description ? <p className={cn("mt-1 text-xs leading-5 text-muted-foreground", variant === "dark" && "text-white/60")}>{description}</p> : null}
          </div>
          <Button className={cn(variant === "dark" && "text-white/70 hover:bg-white/10 hover:text-white")} variant="ghost" size="icon-sm" onClick={() => onOpenChange(false)} aria-label="Close dialog"><X className="h-4 w-4" aria-hidden="true" /></Button>
        </div>
        <div className={cn("px-5 py-5", variant === "dark" && "scrollbar-thin max-h-[70vh] overflow-y-auto text-white")}>{children}</div>
        {footer ? <div className="flex justify-end gap-2 border-t px-5 py-3">{footer}</div> : null}
      </div>
    </div>
  );
}
