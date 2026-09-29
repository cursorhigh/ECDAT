"use client";

import Link from "next/link";
import { Check, Loader2, Play } from "lucide-react";
import { cn } from "@/lib/utils";

export type WorkflowStage = {
  name: string;
  key: string;
  count: number;
  detail: string;
  done: boolean;
  api: string;
  sub?: Array<{ label: string; count: number }>;
};

/** Map a stage's `api` field to the page that shows it. */
const STAGE_ROUTES: Record<string, string> = {
  "/api/scans/": "/scans",
  "/api/assets/": "/assets",
  "/api/analysis/": "/analysis",
  "/api/mitigation/": "/mitigation",
  "/api/reports/full.json": "/reports"
};

/**
 * Turn a stage's backend `api` path into an in-app route.
 *
 * The workflow payload carries API paths, not page paths. Handing one to a
 * Next `<Link>` navigates the client router to a URL that has no page behind
 * it, so the route has to be mapped rather than used verbatim.
 */
export function stageRoute(api?: string): string {
  if (!api) return "/scans";
  if (api.startsWith("/") && !api.startsWith("/api/")) return api;
  return STAGE_ROUTES[api] || "/scans";
}

/**
 * Whole-lifecycle progress: Discover → Assess → Prioritize → Mitigate → Report.
 *
 * Replaces the static header blurb. A scan in this product is only useful once
 * the later stages have run over it, so the bar shows how far through that
 * journey the active scan actually is rather than restating what the page is
 * about.
 *
 * Progress is the share of stages whose output exists, and the highlighted
 * stage is the first one that has not produced anything yet -- so the label
 * always names the next real step instead of the last one that happened to
 * finish.
 */
export function PipelineProgress({
  stages,
  running = false,
  className
}: {
  stages: WorkflowStage[];
  running?: boolean;
  className?: string;
}) {
  const total = stages.length;
  const doneCount = stages.filter((stage) => stage.done).length;
  const percent = total ? Math.round((doneCount / total) * 100) : 0;
  const currentIndex = stages.findIndex((stage) => !stage.done);
  const complete = total > 0 && currentIndex === -1;
  const current = currentIndex === -1 ? null : stages[currentIndex];
  const started = doneCount > 0 || running;

  if (!total) {
    return (
      <div className={cn("border bg-card px-4 py-3", className)}>
        <p className="text-[11px] uppercase tracking-[0.12em] text-muted-foreground">Overall progress</p>
        <p className="mt-1 text-sm text-muted-foreground">
          Run a discovery scan to start the workflow.
        </p>
      </div>
    );
  }

  return (
    <div className={cn("border bg-card px-4 py-3", className)}>
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1">
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
            Overall progress
          </span>
          {running ? (
            <span className="inline-flex items-center gap-1.5 text-[11px] text-primary">
              <Loader2 className="h-3 w-3 animate-spin" aria-hidden="true" />
              Working
            </span>
          ) : null}
        </div>

        <div className="flex items-center gap-2 text-xs">
          <span className="text-muted-foreground">
            {doneCount} of {total} stages
          </span>
          <span aria-hidden="true" className="text-muted-foreground/40">
            |
          </span>
          <span className="font-medium text-foreground">
            {complete ? "Complete" : current ? current.name : "Not started"}
          </span>
        </div>
      </div>

      <div
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={percent}
        aria-valuetext={`${doneCount} of ${total} stages complete${
          current ? `, next: ${current.name}` : ""
        }`}
        aria-label="Discovery to report workflow progress"
        className="mt-2.5 h-1.5 w-full overflow-hidden rounded-full bg-muted"
      >
        <div
          className={cn(
            // Width is the animated part: the bar eases to its new length rather
            // than jumping, which is what makes a stage change legible.
            "h-full rounded-full bg-primary transition-[width] duration-700 ease-out",
            // With work in flight, show motion even though the value has not
            // moved yet -- an unchanging bar next to "Working" reads as stalled.
            running && started && !complete && "animate-pulse"
          )}
          style={{ width: `${started ? Math.max(percent, 4) : 0}%` }}
        />
      </div>

      <ol className="mt-2.5 flex flex-wrap items-center gap-x-1 gap-y-1">
        {stages.map((stage, index) => {
          const isCurrent = index === currentIndex;
          const href = stageRoute(stage.api);
          return (
            <li key={stage.key} className="flex items-center gap-1">
              {index > 0 ? (
                <span aria-hidden="true" className="px-0.5 text-[10px] text-muted-foreground/40">
                  &rsaquo;
                </span>
              ) : null}
              <Link
                href={href}
                title={stage.detail}
                className={cn(
                  "inline-flex items-center gap-1.5 border px-2 py-1 text-[11px] transition-colors",
                  isCurrent
                    ? "border-primary bg-primary/5 font-medium text-foreground"
                    : stage.done
                      ? "border-border text-muted-foreground hover:bg-secondary hover:text-foreground"
                      : "border-transparent text-muted-foreground/60 hover:bg-secondary hover:text-foreground"
                )}
              >
                {stage.done ? (
                  <Check className="h-3 w-3 text-success" aria-hidden="true" />
                ) : isCurrent ? (
                  <Play className="h-3 w-3 text-primary" aria-hidden="true" />
                ) : (
                  <span
                    aria-hidden="true"
                    className="h-1.5 w-1.5 rounded-full bg-current opacity-40"
                  />
                )}
                {stage.name}
                {isCurrent ? <span className="sr-only"> (current stage)</span> : null}
              </Link>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
