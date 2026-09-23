"use client";

import { useEffect } from "react";
import { X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export function Dialog({ open, onOpenChange, title, description, children, footer, className }: { open: boolean; onOpenChange: (open: boolean) => void; title: string; description?: string; children: React.ReactNode; footer?: React.ReactNode; className?: string }) {
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
      <button type="button" className="absolute inset-0 cursor-default bg-background/80 backdrop-blur-[2px]" onClick={() => onOpenChange(false)} aria-label="Close dialog" />
      <div className={cn("relative z-10 w-full max-w-lg border bg-card shadow-2xl", className)}>
        <div className="flex items-start justify-between border-b px-5 py-4">
          <div>
            <h2 id="dialog-title" className="text-base font-semibold">{title}</h2>
            {description ? <p className="mt-1 text-xs leading-5 text-muted-foreground">{description}</p> : null}
          </div>
          <Button variant="ghost" size="icon-sm" onClick={() => onOpenChange(false)} aria-label="Close dialog"><X className="h-4 w-4" aria-hidden="true" /></Button>
        </div>
        <div className="px-5 py-5">{children}</div>
        {footer ? <div className="flex justify-end gap-2 border-t px-5 py-3">{footer}</div> : null}
      </div>
    </div>
  );
}
