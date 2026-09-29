"use client";

import { useEffect, useState, useSyncExternalStore } from "react";
import { createPortal } from "react-dom";
import { X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

/** Must match the dialog-*-out keyframes in globals.css. */
const DIALOG_EXIT_MS = 160;

// Hydration flag, so the portal is only created in the browser. createPortal
// does not exist on the server, and rendering it during SSR throws.
const noopSubscribe = () => () => {};

export function Dialog({ open, onOpenChange, title, description, children, footer, className, variant = "default", dismissible = true }: { open: boolean; onOpenChange: (open: boolean) => void; title: string; description?: string; children: React.ReactNode; footer?: React.ReactNode; className?: string; variant?: "default" | "dark"; dismissible?: boolean }) {
  /**
   * `rendered` is deliberately separate from `open`.
   *
   * Returning null the moment `open` flipped to false meant the exit animation
   * never got a frame to play -- the dialog vanished instantly, which is what
   * made closing feel broken next to how smoothly it opened. So the panel stays
   * mounted for the length of the exit, then unmounts.
   */
  const [rendered, setRendered] = useState(open);
  const [closing, setClosing] = useState(false);
  const mounted = useSyncExternalStore(
    noopSubscribe,
    () => true,
    () => false
  );
  // Previous `open`, kept as state rather than a ref: the eslint react-hooks
  // rules reject reading or writing a ref during render.
  const [previousOpen, setPreviousOpen] = useState(open);

  // React's documented pattern for adjusting state when a prop changes --
  // during render, not in an effect. An effect would render one frame of the
  // old state, and `set-state-in-effect` rejects the direct version.
  if (previousOpen !== open) {
    setPreviousOpen(open);
    if (open) {
      setRendered(true);
      setClosing(false);
    } else {
      setClosing(true);
    }
  }

  // Hold the exit, then unmount. setState here is inside a timer, so it is not
  // the synchronous effect-body update the lint rule objects to.
  useEffect(() => {
    if (!closing) return;
    const timer = setTimeout(() => {
      setClosing(false);
      setRendered(false);
    }, DIALOG_EXIT_MS);
    return () => clearTimeout(timer);
  }, [closing]);

  // Escape closes, but only while genuinely open -- not during the exit.
  // A non-dismissible dialog ignores Escape entirely: it is used for a job that
  // is still running, where leaving the operator with no way out would hide the
  // only progress they have. Cancellation is an explicit action in the footer
  // instead, so there is always exactly one sanctioned way to stop.
  useEffect(() => {
    if (!open || !dismissible) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onOpenChange(false);
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [onOpenChange, open, dismissible]);

  // Scroll stays locked for the whole time the panel is on screen, exit
  // included, so the page behind does not jump as it fades.
  useEffect(() => {
    if (!rendered) return;
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = previous;
    };
  }, [rendered]);

  if (!rendered || !mounted) return null;

  /**
   * Portalled to <body> deliberately.
   *
   * The delete confirmation is opened from the top bar, and the <header> carries
   * `backdrop-blur`. A filter/backdrop-filter makes an element a containing
   * block for `position: fixed` descendants, so a non-portalled `fixed inset-0`
   * overlay sized itself to the header and the dialog appeared pinned to the top
   * of the window. Portalling makes it immune to any ancestor that does this --
   * a transform or `will-change` added elsewhere would break it again.
   */
  return createPortal(
    <div className="fixed inset-0 z-[70] flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="dialog-title">
      <button type="button" data-closing={closing} className="dialog-overlay absolute inset-0 cursor-default bg-background/80 backdrop-blur-[2px]" onClick={() => { if (dismissible) onOpenChange(false); }} aria-label={dismissible ? "Close dialog" : undefined} />
      <div data-closing={closing} className={cn("dialog-panel relative z-10 w-full max-w-lg border shadow-2xl", variant === "dark" ? "bg-black text-white" : "bg-card", className)}>
        <div className="flex items-start justify-between border-b px-5 py-4">
          <div>
            <h2 id="dialog-title" className={cn("text-base font-semibold", variant === "dark" && "text-white")}>{title}</h2>
            {description ? <p className={cn("mt-1 text-xs leading-5 text-muted-foreground", variant === "dark" && "text-white/60")}>{description}</p> : null}
          </div>
          {dismissible ? (
            <Button className={cn(variant === "dark" && "text-white/70 hover:bg-white/10 hover:text-white")} variant="ghost" size="icon-sm" onClick={() => onOpenChange(false)} aria-label="Close dialog"><X className="h-4 w-4" aria-hidden="true" /></Button>
          ) : null}
        </div>
        <div className={cn("px-5 py-5", variant === "dark" && "scrollbar-thin max-h-[70vh] overflow-y-auto text-white")}>{children}</div>
        {footer ? <div className="flex justify-end gap-2 border-t px-5 py-3">{footer}</div> : null}
      </div>
    </div>,
    document.body
  );
}
