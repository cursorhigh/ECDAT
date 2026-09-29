"use client";

import { useEffect, useRef, type RefObject } from "react";

type DismissOptions = {
  /** Only listen while the surface is open. */
  active: boolean;
  /** The element considered "inside". Clicks within it do not dismiss. */
  ref: RefObject<HTMLElement | null>;
  onDismiss: () => void;
  /** Defaults to true. Set false for surfaces that need a different escape key. */
  closeOnEscape?: boolean;
};

/**
 * Dismiss a popover on outside click and on Escape.
 *
 * This exists so there is one implementation instead of one per dropdown. The
 * three surfaces that needed it (the scan switcher, the graph node search and
 * the top-bar delete menu) had drifted: only one of them handled Escape, and
 * one listened for `mousedown` while the others would have wanted `pointerdown`
 * -- which is also what makes it work for touch.
 *
 * `pointerdown` rather than `click` is deliberate: it dismisses before the
 * target's own handler runs, so clicking a control that unmounts the popover
 * does not leave a stale panel on screen.
 */
export function useDismissOnOutside({
  active,
  ref,
  onDismiss,
  closeOnEscape = true
}: DismissOptions) {
  // Held in a ref so an inline arrow from the caller does not re-subscribe the
  // listeners on every render. Written in an effect rather than during render
  // (react-hooks/refs), and declared first so it has run by the time the
  // listener effect below fires.
  const dismissRef = useRef(onDismiss);
  useEffect(() => {
    dismissRef.current = onDismiss;
  }, [onDismiss]);

  useEffect(() => {
    if (!active) return;

    const onPointerDown = (event: PointerEvent) => {
      const node = ref.current;
      if (!node) return;
      const target = event.target as Node | null;
      if (target && node.contains(target)) return;
      dismissRef.current();
    };

    const onKeyDown = (event: KeyboardEvent) => {
      if (!closeOnEscape || event.key !== "Escape") return;
      dismissRef.current();
    };

    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [active, ref, closeOnEscape]);
}
