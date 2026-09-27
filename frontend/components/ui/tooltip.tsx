"use client";

import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { CircleHelp } from "lucide-react";
import { cn } from "@/lib/utils";

export type TooltipPlacement = "top" | "right" | "bottom" | "left";

export type TooltipProps = {
  /** Content shown while the trigger is hovered or focused. */
  msg: ReactNode;
  className?: string;
  triggerClassName?: string;
  iconClassName?: string;
  tooltipClassName?: string;
  placement?: TooltipPlacement;
  offset?: number;
  /** Transient message after a click action resolves. */
  clickMsg?: ReactNode;
  clickErrorMsg?: ReactNode;
  onClick?: () => void | Promise<void>;
  children?: ReactNode;
};

/**
 * Portal-rendered tooltip that follows the cursor, so it never gets clipped by
 * an overflow-hidden ancestor or trapped inside a card.
 *
 * Reachable by keyboard as well as pointer: the trigger is focusable and the
 * bubble is wired with aria-describedby, so the information is not mouse-only.
 */
export function Tooltip({
  msg,
  className,
  triggerClassName,
  iconClassName,
  tooltipClassName,
  placement = "top",
  offset = 10,
  clickMsg,
  clickErrorMsg,
  onClick,
  children,
}: TooltipProps) {
  const [activeMsg, setActiveMsg] = useState<ReactNode>(null);
  const [showTemp, setShowTemp] = useState(false);
  const [isHover, setIsHover] = useState(false);
  const [isFocus, setIsFocus] = useState(false);
  const [position, setPosition] = useState<{ left: number; top: number } | null>(null);
  const [cursor, setCursor] = useState<{ x: number; y: number } | null>(null);
  const triggerRef = useRef<HTMLSpanElement | null>(null);
  const bubbleId = `tooltip-${useId()}`;

  useEffect(() => {
    if (!showTemp) return;
    const timer = setTimeout(() => {
      setShowTemp(false);
      setActiveMsg(null);
    }, 1600);
    return () => clearTimeout(timer);
  }, [showTemp]);

  const handleClick = async () => {
    if (!onClick) return;
    try {
      await onClick();
      if (clickMsg !== undefined) {
        setActiveMsg(clickMsg);
        setShowTemp(true);
      }
    } catch {
      if (clickErrorMsg !== undefined) {
        setActiveMsg(clickErrorMsg);
        setShowTemp(true);
      }
    }
  };

  const tooltipText = activeMsg ?? msg;
  const isVisible = isHover || isFocus || showTemp;

  useEffect(() => {
    if (!isVisible) return;

    const updatePosition = () => {
      if (cursor) {
        setPosition({ left: cursor.x, top: cursor.y });
        return;
      }
      const rect = triggerRef.current?.getBoundingClientRect();
      if (!rect) return;
      setPosition({ left: rect.left + rect.width / 2, top: rect.top + rect.height / 2 });
    };

    updatePosition();
    window.addEventListener("scroll", updatePosition, true);
    window.addEventListener("resize", updatePosition);
    return () => {
      window.removeEventListener("scroll", updatePosition, true);
      window.removeEventListener("resize", updatePosition);
    };
  }, [isVisible, cursor]);

  const tooltipStyle = (): React.CSSProperties | undefined => {
    if (!position) return undefined;
    switch (placement) {
      case "right":
        return { left: position.left + offset, top: position.top, transform: "translateY(-50%)" };
      case "bottom":
        return { left: position.left, top: position.top + offset, transform: "translateX(-50%)" };
      case "left":
        return {
          left: position.left - offset,
          top: position.top,
          transform: "translate(-100%, -50%)",
        };
      default:
        return {
          left: position.left,
          top: position.top - offset,
          transform: "translate(-50%, -100%)",
        };
    }
  };

  const trigger = children ? (
    <span className={cn("inline-flex items-center", triggerClassName)}>{children}</span>
  ) : (
    <CircleHelp
      aria-hidden="true"
      className={cn("h-4 w-4 text-muted-foreground transition-colors hover:text-foreground", iconClassName)}
    />
  );

  const interactive = Boolean(onClick);

  return (
    <span className={cn("relative inline-flex items-center", className)}>
      <span
        ref={triggerRef}
        onMouseEnter={() => setIsHover(true)}
        onMouseLeave={() => {
          setIsHover(false);
          setCursor(null);
        }}
        onMouseMove={(event) => setCursor({ x: event.clientX, y: event.clientY })}
        onFocus={() => setIsFocus(true)}
        onBlur={() => setIsFocus(false)}
        className="inline-flex items-center"
      >
        {interactive ? (
          <button
            type="button"
            onClick={handleClick}
            className="cursor-pointer inline-flex items-center"
            aria-label="More info"
          >
            {trigger}
          </button>
        ) : children ? (
          // The caller supplied its own focusable control (a button, a link).
          // React's onFocus/onBlur propagate, so its focus already opens the
          // bubble; adding tabIndex here would create a second tab stop.
          <span aria-describedby={isVisible ? bubbleId : undefined} className="inline-flex">
            {trigger}
          </span>
        ) : (
          <span
            tabIndex={0}
            aria-describedby={isVisible ? bubbleId : undefined}
            className="inline-flex cursor-help items-center"
          >
            {trigger}
          </span>
        )}
      </span>

      {isVisible && position
        ? createPortal(
            <span
              id={bubbleId}
              role="tooltip"
              className={cn(
                "pointer-events-none fixed z-[9999] max-w-[280px] whitespace-normal rounded-sm border border-border bg-popover px-2.5 py-1.5 text-xs leading-4 text-popover-foreground shadow-lg",
                tooltipClassName,
              )}
              style={tooltipStyle()}
            >
              {tooltipText}
            </span>,
            document.body,
          )
        : null}
    </span>
  );
}

export default Tooltip;
