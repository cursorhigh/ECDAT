"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, Clock, Globe, Loader2, ShieldAlert, SlidersHorizontal, Sparkles, Timer } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Input, Label, Select } from "@/components/ui/input";
import { useToast } from "@/components/feedback/toast";
import { api } from "@/lib/api/client";
import type { ScanJob } from "@/lib/api/types";
import { cn } from "@/lib/utils";

/**
 * Statuses that mean the scan is still doing work, so correlation has not run yet.
 */
const IN_FLIGHT = new Set(["queued", "validating", "running", "cancelling"]);

/**
 * `partial` is deliberately NOT analyzable.
 *
 * The backend rejects it (`analysis/views.py:150` requires exactly COMPLETED), so
 * offering it here would only ever produce a 400. A partial scan means coverage
 * was incomplete, and that gap has to be closed by re-scanning, not reasoned over.
 */
/*
 * Scans that finished producing evidence, and can therefore be reasoned over.
 *
 * `partial` belongs here alongside `completed`. A partial scan is not a failure:
 * it means every source ran and one or more files were unreadable, and the
 * backend records exactly what was missed on the run's `coverage` field so the
 * assessment states its own limits. The old completed-only rule here disagreed
 * with the backend, which accepts both -- so a finished scan produced this
 * "Risk analysis locked" message and refused the very analysis the pipeline had
 * already staged.
 */
const ANALYZABLE_STATUS = new Set(["completed", "partial"]);

export interface RiskGate {
  /** Scans that finished, i.e. inspection finished AND correlation has run. */
  analyzable: ScanJob[];
  /** Scans still in progress, for the "why is this locked" message. */
  inFlight: number;
  /** Scans that finished but cannot be analyzed (failed/cancelled). */
  unusable: number;
  locked: boolean;
  reason: string;
}

/**
 * Decide whether risk analysis may be offered for a session's scans.
 *
 * The rule mirrors the discovery pipeline: `build_correlations` runs at
 * `services.py:613`, and the terminal status is not written until `services.py:644`.
 * So any terminal status is proof that inspection *and* correlation both
 * finished, which is exactly what the backend demands before reasoning.
 */
export function evaluateRiskGate(scans: ScanJob[] | undefined, hasSession: boolean): RiskGate {
  const list = scans || [];
  const analyzable = list.filter((scan) => ANALYZABLE_STATUS.has(scan.status));
  const inFlight = list.filter((scan) => IN_FLIGHT.has(scan.status)).length;
  const unusable = list.length - analyzable.length - inFlight;

  if (!hasSession) {
    return { analyzable, inFlight, unusable, locked: true, reason: "No scan selected. Open or start a discovery scan first." };
  }
  if (analyzable.length > 0) {
    return { analyzable, inFlight, unusable, locked: false, reason: "" };
  }
  if (inFlight > 0) {
    return {
      analyzable,
      inFlight,
      unusable,
      locked: true,
      reason: `Discovery is still running on ${inFlight} scan${inFlight === 1 ? "" : "s"}. Correlation runs after inspection, so risk analysis unlocks once the scan completes.`
    };
  }
  if (list.length > 0) {
    return {
      analyzable,
      inFlight,
      unusable,
      locked: true,
      reason: `No finished scan in this session. Risk analysis needs a scan whose inspection and correlation have both completed${unusable > 0 ? ` (${unusable} scan${unusable === 1 ? "" : "s"} failed or was cancelled)` : ""}.`
    };
  }
  return { analyzable, inFlight, unusable, locked: true, reason: "This session has no scans yet. Run a discovery scan first." };
}

interface RiskStartDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Completed scans this session. The dialog only ever offers these. */
  candidates: ScanJob[];
  /** Pre-select a specific scan (used when resuming an AWAITING_CONTEXT run). */
  initialScanId?: number | null;
  /**
   * Seconds the server will wait before queuing the run with defaults, as
   * reported by /analysis/start/. `null` means no run is parked yet, so there is
   * nothing counting down; `0` means the window has already closed.
   */
  deadlineSeconds?: number | null;
}

/**
 * Collects the operational context MOSCA (X + Y > Z) and HNDL need.
 *
 * The run is started by the caller before this opens (see `defer` on
 * /analysis/start/): the analysis row already exists in AWAITING_CONTEXT while
 * this form is up. Submitting supplies the answers, which resumes that same
 * run. Closing it or letting the countdown lapse leaves the run to fall back to
 * the conservative server-side defaults, so the assessment still completes
 * without the operator.
 */
/**
 * Owns the countdown for the parked run's context window.
 *
 * This has to live in `RiskStartDialog` rather than inside `ContextWindow`: the
 * submit button must disable the moment the window lapses, and a child owning
 * the timer leaves the parent unable to see it reach zero. The backend is the
 * authority (it queues the run with the defaults regardless), so this only has
 * to stay in step with the deadline it was handed.
 *
 * `from` remembers which deadline the current count belongs to. When the server
 * reports a new one the count is reset during render, which is React's
 * sanctioned way to react to a changed prop -- doing it in an effect instead
 * costs an extra render pass and trips `set-state-in-effect`. Re-syncing from
 * the server is also more accurate than a free-running timer, which drifts
 * against the real `await_until`.
 */
function useContextCountdown(seconds: number | null) {
  const [countdown, setCountdown] = useState({ from: seconds, remaining: seconds ?? 0 });

  if (countdown.from !== seconds) {
    setCountdown({ from: seconds, remaining: seconds ?? 0 });
  }

  useEffect(() => {
    if (seconds === null || seconds <= 0) return;
    const timer = setInterval(() => {
      setCountdown((value) => ({ ...value, remaining: Math.max(0, value.remaining - 1) }));
    }, 1000);
    return () => clearInterval(timer);
  }, [seconds]);

  return countdown.remaining;
}

/**
 * Status of the context window, with a live countdown.
 *
 * Presentational only: the timer lives in the dialog so the submit button can
 * react to it reaching zero.
 */
function ContextWindow({ seconds, remaining }: { seconds: number | null; remaining: number }) {
  /*
   * No deadline means a deliberate start: the operator pressed the button and
   * nobody is timing them. Showing "No analysis is waiting yet" there was both
   * confusing and untrue -- a run genuinely is not parked, but that is the
   * point, not a warning. So the strip is omitted entirely and the form gets
   * the full attention.
   */
  if (seconds === null) return null;

  if (remaining === 0) {
    return (
      <div className="flex items-start gap-2 border border-success/30 bg-success/5 p-2.5">
        <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-success" aria-hidden="true" />
        <span>
          The window closed, so the analysis continued with the <span className="font-semibold">default</span>{" "}
          parameters. Close this to watch it run, then use{" "}
          <span className="font-semibold"> Run Risk Analysis</span> again to re-apply your own values to
          the same discovered assets.
        </span>
      </div>
    );
  }

  return (
    <div className="flex items-center justify-between gap-4 border border-warning/40 bg-warning/5 p-3">
      <div className="flex min-w-0 items-start gap-2">
        <Timer className="mt-1 h-4 w-4 shrink-0 text-warning" aria-hidden="true" />
        <span className="text-xs leading-5 text-muted-foreground">
          Analysis has started and is waiting for these parameters. If you do nothing it continues with{" "}
          <span className="font-semibold text-foreground">conservative defaults</span>.
        </span>
      </div>
      {/*
        Seconds, not m:ss. The window is 60s, so a minutes field can only ever
        read "0:59" down to "0:00" -- the digit that actually matters is the
        units one, and it was the smallest thing on screen. Shown large and
        right-aligned so it is the first thing read.
      */}
      <div className="flex shrink-0 items-baseline gap-1.5" role="timer" aria-live="off">
        <span className="tnum text-3xl font-semibold leading-none tracking-tight text-warning">
          {remaining}
        </span>
        <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
          {remaining === 1 ? "second" : "seconds"}
        </span>
      </div>
    </div>
  );
}

export function RiskStartDialog({ open, onOpenChange, candidates, initialScanId, deadlineSeconds = null }: RiskStartDialogProps) {
  const router = useRouter();
  const { pushToast } = useToast();

  const [dataLifetimeYears, setDataLifetimeYears] = useState("8.0");
  const [migrationComplexity, setMigrationComplexity] = useState("3.0");
  const [quantumHorizonYear, setQuantumHorizonYear] = useState("2033");
  const [dataSensitivity, setDataSensitivity] = useState("4");
  const [isPublicAccess, setIsPublicAccess] = useState(true);
  const [customAppName, setCustomAppName] = useState("");
  const [chosenScanId, setChosenScanId] = useState<number | null>(null);

  // Filtered here as well as at the call site, so a caller can never hand this
  // dialog a scan the backend would reject. `evaluateRiskGate` is for the button
  // state; this is the guarantee on the actual submit path.
  // `.has`, not `===`: ANALYZABLE_STATUS is a Set, and comparing a string to it
  // would be truthy for every scan and hand the dialog scans still in progress.
  const analyzable = useMemo(
    () => candidates.filter((scan) => ANALYZABLE_STATUS.has(scan.status)),
    [candidates]
  );

  // `initialScanId` wins when resuming; otherwise fall back to the newest finished scan.
  const preferred = initialScanId && analyzable.some((scan) => scan.id === initialScanId) ? initialScanId : null;
  const targetId = chosenScanId ?? preferred ?? analyzable[0]?.id ?? null;

  /**
   * The countdown is owned by the backend (`pending_analysis` sets `await_until`
   * and a timer that queues the run with the conservative defaults). This only
   * mirrors that window so the operator can see how long they have, and the
   * deadline is passed in from the response rather than invented here.
   *
   * When it lapses the run is already queued server-side, so the form is
   * disabled rather than pretending the answers could still be applied. `null`
   * means nothing is parked, in which case applying is how a run gets started
   * and the form must stay live.
   */
  const remaining = useContextCountdown(deadlineSeconds);
  const expired = deadlineSeconds !== null && remaining === 0;
  /**
   * A deliberate start has no server-side deadline, so nothing is counting the
   * operator down and the form must never lock under them.
   */
  const deliberate = deadlineSeconds === null;

  const startRiskAnalysis = useMutation({
    mutationFn: async () => {
      if (!targetId) throw new Error("Choose a completed scan first.");
      const rawContext = {
        application: {
          name: customAppName || "ECDAT Target Systems",
          type: "enterprise_service"
        },
        data: {
          lifetime_years: Number(dataLifetimeYears) || 8.0,
          sensitivity: Number(dataSensitivity) || 4,
          types: ["PII", "Financial", "SessionTokens"]
        },
        network: {
          publicly_accessible: isPublicAccess,
          internet_facing: isPublicAccess
        },
        business_context: {
          data_retention_years: Number(dataLifetimeYears) || 8.0,
          migration_complexity: Number(migrationComplexity) || 3,
          quantum_horizon_year: Number(quantumHorizonYear) || 2033,
          assessment_year: 2026
        },
        operational_parameters: {
          X_migration_time_years: Number(migrationComplexity) || 3.0,
          Y_data_lifetime_years: Number(dataLifetimeYears) || 8.0,
          Z_quantum_horizon_year: Number(quantumHorizonYear) || 2033
        }
      };
      // No `defer` either way. When a run is already parked this resumes it; on
      // a deliberate start there is nothing to resume, so the backend creates the
      // run here from the answers that were just supplied.
      return api.startAnalysis({ scan_job: Number(targetId), raw_system_context: rawContext });
    },
    onSuccess: (created) => {
      onOpenChange(false);
      pushToast(`Quantum Risk Analysis #${created.id} started successfully!`, "success");
      router.push("/analysis");
    },
    onError: (error) => pushToast(error instanceof Error ? error.message : "Failed to start risk analysis.", "error")
  });

  /**
   * Commit the parked run on the conservative defaults, right now.
   *
   * Sending no `raw_system_context` is what makes this "use the defaults": the
   * backend keeps the context the run was created with and simply dispatches it.
   * A raw context here would be the same as pressing Apply with the pre-filled
   * values, which is not what this button claims to do.
   */
  const useDefaults = useMutation({
    mutationFn: () => {
      if (!targetId) throw new Error("No scan is waiting for parameters.");
      return api.startAnalysis({ scan_job: Number(targetId) });
    },
    onSuccess: (created) => {
      onOpenChange(false);
      pushToast(
        `Analysis #${created.id} started with the default parameters.`,
        "success"
      );
    },
    onError: (error) =>
      pushToast(
        error instanceof Error ? error.message : "The analysis could not be started.",
        "error"
      ),
  });

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Operational Threat & Timeline Parameters"
      description="Provide organizational context for Michele Mosca's Theorem (X + Y > Z) and HNDL (Harvest-Now-Decrypt-Later) Threat Scoring."
      footer={
        <>
          {/*
            This used to only call onOpenChange(false) -- it closed the dialog and
            did nothing else, so the run sat in AWAITING_CONTEXT until the server's
            own deadline timer happened to fire. The button said "Use defaults" and
            then didn't use them.

            It now commits them: startAnalysis with no raw_system_context resolves
            the parked run server-side, which flips AWAITING_CONTEXT to QUEUED and
            dispatches it on the conservative defaults it was already created with.
            So the button does what it says and the run actually starts.
          */}
          <Button
            variant="ghost"
            onClick={() => (deliberate ? onOpenChange(false) : useDefaults.mutate())}
            disabled={startRiskAnalysis.isPending || useDefaults.isPending}
          >
            {expired ? "Close" : deliberate ? "Cancel" : "Use defaults"}
          </Button>
          <Button
            onClick={() => startRiskAnalysis.mutate()}
            disabled={startRiskAnalysis.isPending || !targetId || expired}
          >
            {startRiskAnalysis.isPending ? (
              <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
            ) : (
              <Sparkles className="mr-1.5 h-3.5 w-3.5" />
            )}
            Apply and run
          </Button>
        </>
      }
    >
      <div className="space-y-4 text-xs">
        <ContextWindow seconds={deadlineSeconds} remaining={remaining} />
        {analyzable.length > 1 ? (
          <div className="space-y-1.5">
            <Label className="font-medium">Scan to analyze</Label>
            <Select value={targetId != null ? String(targetId) : ""} onChange={(e) => setChosenScanId(Number(e.target.value))}>
              {analyzable.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  {scan.target} ({scan.findings_count} findings)
                </option>
              ))}
            </Select>
            <p className="text-[10px] text-muted-foreground">Only finished scans are listed. Partial scans show their coverage gap on the assessment.</p>
          </div>
        ) : null}

        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1.5">
            <Label className="flex items-center gap-1.5 font-medium">
              <Clock className="h-3.5 w-3.5 text-primary" />
              Data Shelf-Life (Y years)
            </Label>
            <Input
              type="number"
              step="0.5"
              value={dataLifetimeYears}
              onChange={(e) => setDataLifetimeYears(e.target.value)}
              placeholder="e.g. 8.0"
            />
            <p className="text-[10px] text-muted-foreground">Years data must remain secret.</p>
          </div>

          <div className="space-y-1.5">
            <Label className="flex items-center gap-1.5 font-medium">
              <SlidersHorizontal className="h-3.5 w-3.5 text-primary" />
              Migration Duration (X years)
            </Label>
            <Input
              type="number"
              step="0.5"
              value={migrationComplexity}
              onChange={(e) => setMigrationComplexity(e.target.value)}
              placeholder="e.g. 3.0"
            />
            <p className="text-[10px] text-muted-foreground">Years to migrate all infrastructure.</p>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1.5">
            <Label className="flex items-center gap-1.5 font-medium">
              <ShieldAlert className="h-3.5 w-3.5 text-destructive" />
              CRQC Horizon Year (Z)
            </Label>
            <Input
              type="number"
              value={quantumHorizonYear}
              onChange={(e) => setQuantumHorizonYear(e.target.value)}
              placeholder="e.g. 2033"
            />
            <p className="text-[10px] text-muted-foreground">Expected year quantum computers break classical crypto.</p>
          </div>

          <div className="space-y-1.5">
            <Label className="flex items-center gap-1.5 font-medium">Data Sensitivity Tier</Label>
            <Select value={dataSensitivity} onChange={(e) => setDataSensitivity(e.target.value)}>
              <option value="5">Tier 5 - Top Secret / Critical Infrastructure</option>
              <option value="4">Tier 4 - High (PII / Financial / Auth Tokens)</option>
              <option value="3">Tier 3 - Medium (Confidential Internal)</option>
              <option value="2">Tier 2 - Low (Internal Operational)</option>
              <option value="1">Tier 1 - Public Non-sensitive</option>
            </Select>
          </div>
        </div>

        <div className="space-y-1.5">
          <Label className="flex items-center gap-1.5 font-medium">
            <Globe className="h-3.5 w-3.5 text-primary" />
            Network Exposure
          </Label>
          <Select value={isPublicAccess ? "public" : "internal"} onChange={(e) => setIsPublicAccess(e.target.value === "public")}>
            <option value="public">Public / Internet-Facing</option>
            <option value="internal">Internal / Private Mesh</option>
          </Select>
        </div>

        <div className="space-y-1.5">
          <Label className="font-medium">System / Application Label</Label>
          <Input
            value={customAppName}
            onChange={(e) => setCustomAppName(e.target.value)}
            placeholder="e.g. Enterprise Core Services &amp; Key Vault"
          />
        </div>

        <div className="rounded border bg-muted/40 p-2.5 text-[11px] leading-relaxed text-muted-foreground">
          <span className="font-medium text-foreground">Mosca Inequality Theorem:</span> If Migration Time (
          <span className="font-semibold text-primary">{migrationComplexity}y</span>) + Shelf-Life (
          <span className="font-semibold text-primary">{dataLifetimeYears}y</span>) &gt; Quantum Arrival (
          <span className="font-semibold text-primary">{Number(quantumHorizonYear) - 2026}y</span>), then data is ALREADY
          vulnerable to Harvest Now Decrypt Later.
        </div>
      </div>
    </Dialog>
  );
}

/**
 * The readiness line rendered above the assets table.
 *
 * It states the precondition in plain words rather than leaving a silently
 * disabled button, so a locked gate is never mistaken for a broken page.
 */
export function RiskReadinessNote({ gate }: { gate: RiskGate }) {
  if (gate.locked) {
    return (
      <div className="flex items-start gap-2 border border-warning/40 bg-warning/5 px-3 py-2 text-xs text-muted-foreground">
        <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-warning" aria-hidden="true" />
        <span>
          <span className="font-medium text-foreground">Risk analysis locked.</span> {gate.reason}
        </span>
      </div>
    );
  }
  return (
    <div className="flex items-start gap-2 border border-success/40 bg-success/5 px-3 py-2 text-xs text-muted-foreground">
      <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-success" aria-hidden="true" />
      <span>
        <span className="font-medium text-foreground">Ready for risk analysis.</span> Discovery and correlation have completed for{" "}
        {gate.analyzable.length} scan{gate.analyzable.length === 1 ? "" : "s"} in this session.
        {gate.inFlight > 0 ? ` ${gate.inFlight} scan${gate.inFlight === 1 ? " is" : "s are"} still running and excluded.` : ""}
      </span>
    </div>
  );
}
