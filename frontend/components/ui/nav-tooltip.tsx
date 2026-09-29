"use client";

import { useEffect, useId, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { cn } from "@/lib/utils";

export type NavTooltipProps = {
  /** Bold first line. Keep it to a few words. */
  title: ReactNode;
  /** Optional second line, muted, wraps to two or three lines. */
  description?: ReactNode;
  side?: "top" | "bottom";
  /** Destructive tone, for actions that remove data. */
  tone?: "default" | "destructive";
  /** Suppress the bubble, e.g. while the trigger's own menu is open. */
  disabled?: boolean;
  className?: string;
  children: ReactNode;
};

type Rect = { left: number; top: number; width: number; height: number };

const EDGE_GAP = 10;
const FLIP_THRESHOLD = 96;

/**
 * Anchored tooltip for the top bar.
 *
 * The existing `Tooltip` in this repo follows the cursor, which is right for
 * inline help inside a card but feels loose on a row of fixed controls: the
 * bubble drifts away from the thing it describes. This one anchors to the
 * trigger's centre, flips below when there is no room above, and keeps the
 * bubble clear of the viewport edges.
 *
 * It deliberately adds no `tabIndex` of its own. The controls it wraps are
 * already focusable, and focus events bubble, so keyboard users get the same
 * bubble without a second, redundant tab stop.
 */
export function NavTooltip({ title, description, side = "top", tone = "default", disabled = false, className, children }: NavTooltipProps) {
  const [open, setOpen] = useState(false);
  const shown = open && !disabled;
  const [rect, setRect] = useState<Rect | null>(null);
  const [placement, setPlacement] = useState<"top" | "bottom">(side);
  const anchorRef = useRef<HTMLSpanElement | null>(null);
  const bubbleId = `nav-tip-${useId()}`;

  useLayoutEffect(() => {
    // No cleanup on close is needed: the bubble is only rendered when `open`
    // is true, and a stale rect is simply never read.
    if (!shown) return;
    const measure = () => {
      const element = anchorRef.current;
      if (!element) return;
      const next = element.getBoundingClientRect();
      setRect({ left: next.left, top: next.top, width: next.width, height: next.height });
      // Flip below when the trigger sits too close to the top of the viewport.
      setPlacement(side === "top" && next.top < FLIP_THRESHOLD ? "bottom" : side);
    };
    measure();
    window.addEventListener("scroll", measure, true);
    window.addEventListener("resize", measure);
    return () => {
      window.removeEventListener("scroll", measure, true);
      window.removeEventListener("resize", measure);
    };
  }, [shown, side]);

  useEffect(() => {
    if (!shown) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [shown]);

  const style = (): React.CSSProperties | undefined => {
    if (!rect) return undefined;
    const centreX = rect.left + rect.width / 2;
    // Clamp so a wide bubble never runs off the side of a narrow window.
    const left = Math.min(Math.max(centreX, 148), window.innerWidth - 148);
    if (placement === "bottom") {
      return { left, top: rect.top + rect.height + EDGE_GAP, transform: "translateX(-50%)" };
    }
    return { left, top: rect.top - EDGE_GAP, transform: "translateX(-50%)" };
  };

  return (
    <span
      ref={anchorRef}
      className={cn("inline-flex", className)}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
    >
      <span aria-describedby={shown ? bubbleId : undefined} className="inline-flex">
        {children}
      </span>

      {shown && rect
        ? createPortal(
            // Outer element owns positioning only; inner element owns the
            // entrance animation. Keeping them apart stops the keyframe
            // transform from clobbering the horizontal centring.
            <span
              style={style()}
              className="pointer-events-none fixed z-[9999] flex w-max max-w-[calc(100vw-24px)]"
            >
              <span
                id={bubbleId}
                role="tooltip"
                data-side={placement}
              className={cn(
                "nav-tooltip pointer-events-none relative flex w-max max-w-[300px] flex-col gap-0.5 rounded-md border px-2.5 py-2 text-left shadow-lg",
                // Inventory data is full of single unbroken tokens -- absolute
                // Windows paths, 32-char identifiers, long algorithm names. The
                // default `overflow-wrap: normal` leaves those intact, so they
                // ran straight past the max-width instead of wrapping. `anywhere`
                // breaks inside a word when it has to, which is the only thing
                // that makes these values readable in a fixed-width bubble.
                "[overflow-wrap:anywhere] break-words",
                tone === "destructive"
                  ? "border-destructive/40 bg-popover text-popover-foreground"
                  : "border-border bg-popover text-popover-foreground"
              )}
              >
                <span
                  className={cn(
                    "text-[11px] font-semibold leading-4",
                    tone === "destructive" ? "text-destructive" : "text-foreground"
                  )}
                >
                  {title}
                </span>
                {description ? (
                  <span className="text-[11px] leading-[1.35rem] text-muted-foreground">{description}</span>
                ) : null}
                <span
                  aria-hidden="true"
                  className={cn(
                    "absolute left-1/2 size-2 -translate-x-1/2 rotate-45 border bg-popover",
                    placement === "top" ? "-bottom-1 border-b border-r" : "-top-1 border-l border-t",
                    tone === "destructive" && "border-destructive/40"
                  )}
                />
              </span>
            </span>,
            document.body
          )
        : null}
    </span>
  );
}

export default NavTooltip;
