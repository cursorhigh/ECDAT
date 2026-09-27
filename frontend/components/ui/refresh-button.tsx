"use client";

import { useState } from "react";
import { RefreshCw } from "lucide-react";
import { Button, type ButtonProps } from "@/components/ui/button";
import { useToast } from "@/components/feedback/toast";
import { cn } from "@/lib/utils";

type RefreshButtonProps = Omit<ButtonProps, "onClick" | "children"> & {
  onRefresh: () => void | Promise<unknown>;
  label?: string;
  showLabel?: boolean;
  successMessage?: string;
};

export function RefreshButton({ onRefresh, label = "Refresh", showLabel = true, successMessage, className, variant = "outline", size = "sm", disabled, ...props }: RefreshButtonProps) {
  const [pending, setPending] = useState(false);
  const { pushToast } = useToast();
  const run = async () => {
    if (pending) return;
    const startedAt = Date.now();
    setPending(true);
    try {
      await onRefresh();
      pushToast(successMessage || `${label} complete.`, "success");
    } catch (error) {
      // A react-query refetch resolves rather than throws on failure, so
      // callers must surface errors themselves (see refetchAllOrThrow).
      pushToast(
        error instanceof Error && error.message
          ? error.message
          : `${label} failed. Some data may be out of date.`,
        "error",
      );
    } finally {
      const remaining = Math.max(0, 350 - (Date.now() - startedAt));
      if (remaining) await new Promise((resolve) => window.setTimeout(resolve, remaining));
      setPending(false);
    }
  };

  return <Button type="button" variant={variant} size={size} className={cn(className)} disabled={pending || disabled} onClick={() => void run()} aria-busy={pending} aria-label={props["aria-label"] || label} {...props}><RefreshCw className={cn("h-3.5 w-3.5", pending && "animate-spin")} aria-hidden="true" />{showLabel ? label : null}</Button>;
}
