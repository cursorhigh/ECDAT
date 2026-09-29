"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { RiskStartDialog } from "@/components/data/risk-start-dialog";
import {
  isRiskPromptSurfaced,
  markRiskPromptSurfaced,
  onRiskPromptRequest,
  type RiskPromptRequest,
} from "@/components/data/risk-prompt-store";
import { useToast } from "@/components/feedback/toast";
import { api } from "@/lib/api/client";
import type { ScanJob } from "@/lib/api/types";

/**
 * How often to re-check for a parked run.
 *
 * The modal is an interrupt, so latency matters more than request volume here:
 * at 4s the worst case between a run being parked and the modal appearing is
 * one poll, which reads as "it just appeared" rather than "something is broken".
 */
const POLL_MS = 4000;

interface OpenState {
  scanJobId: number;
  deadlineSeconds: number | null;
  /**
   * "polled" runs are cleared as soon as the awaiting list empties, because the
   * poller is their only source of truth. "requested" runs were opened by a page
   * that just started them, so the poller must not close them out from under it
   * during the request's own round trip.
   */
  source: "polled" | "requested";
}

/**
 * The single mount point for the operational-context modal.
 *
 * Mounted once in the workspace layout rather than per page, for two reasons:
 *
 *  1. A parked run is created *before* the questions are answered, so it is a
 *     pending obligation that outlives navigation. The operator can start risk
 *     analysis, wander to Graph, and the backend is still counting down. If the
 *     prompt only lived on the page that started it, navigating away would hide
 *     the one question that decides what the assessment says.
 *  2. One mount means one dialog. Rendering a copy per page is how the same run
 *     ended up being asked about twice.
 *
 * It opens from two directions -- the poller below, and an explicit request from
 * a page that just started a run -- but both funnel through the same state, so
 * there is only ever one modal.
 */
export function RiskContextPrompt() {
  const { pushToast } = useToast();
  // The run currently being put in front of the operator, and the one they
  // dismissed. Both are needed: a dismissed run must stay dismissed, so
  // "closed" cannot simply mean "open === false".
  const [openState, setOpenState] = useState<OpenState | null>(null);
  const [dismissedKey, setDismissedKey] = useState<string | null>(null);

  const awaiting = useQuery({
    queryKey: ["analysis-awaiting", "global-prompt"],
    queryFn: api.analysisAwaiting,
    refetchInterval: POLL_MS,
    // Parked runs are rare, so only pay for the poll once the page has settled.
    staleTime: POLL_MS,
  });

  const parked = awaiting.data ?? [];

  /**
   * Parked runs are deliberately NOT prompted for.
   *
   * This used to adopt the newest parked run and interrupt the operator with the
   * modal, which is wrong on two counts: it asked even when nobody had asked for
   * an analysis, and it interrupted whatever they were doing. The intended flow
   * is that discovery finishing lets its own analysis run on unattended -- the
   * last-used context, or the conservative defaults -- and the modal appears only
   * when someone presses Start analysis.
   *
   * So the poll below still runs, but only to keep the run list fresh for the
   * analysis page. It never opens anything by itself.
   */
  void parked;

  /**
   * A page that just pressed "Run Risk Analysis" asks here to open.
   *
   * A deliberate press deliberately does NOT park a run. Parking means the
   * backend starts a 60-second auto-continue, so the operator would be filling
   * the form in against a clock they never asked for -- and closing it would
   * still launch the assessment on defaults. `start` therefore only opens the
   * form; the run is created on submit, with whatever they filled in.
   */
  useEffect(
    () =>
      onRiskPromptRequest((request: RiskPromptRequest) => {
        if (request.kind === "start") {
          setOpenState({ scanJobId: request.scanJobId, deadlineSeconds: null, source: "requested" });
          return;
        }
        setOpenState({
          scanJobId: request.scanJobId,
          deadlineSeconds: request.deadlineSeconds ?? null,
          source: "requested",
        });
      }),
    []
  );

  /**
   * Identity of what is open, used both as the React key and to remember a
   * dismissal.
   *
   * Deliberately the scan id only. This used to include `deadlineSeconds`, which
   * the poller refreshes every few seconds as the window counts down -- so the
   * key changed constantly and React remounted the dialog on each one. The old
   * `Dialog` portal was still in the document when the new one mounted, which is
   * why the same modal appeared twice.
   *
   * The countdown lives in the dialog's own state, so it does not need a remount
   * to advance, and re-seeding it from the server still happens because the prop
   * is re-synced whenever it changes.
   */
  const openKey = openState ? String(openState.scanJobId) : null;
  const open = openState !== null && openKey !== dismissedKey;

  /**
   * The dialog needs a completed scan to attach the answers to. The scan id is
   * enough to submit; the full scan list is only needed to offer a *choice*,
   * which a single parked run has no business doing.
   */
  const candidates = useMemo<ScanJob[]>(
    () =>
      openState
        ? [{ id: openState.scanJobId, target: "", status: "completed" } as ScanJob]
        : [],
    [openState]
  );

  const handleOpenChange = useCallback(
    (nextOpen: boolean) => {
      if (nextOpen || !openState) return;
      setDismissedKey(String(openState.scanJobId));
      pushToast(
        "The analysis is running with the default parameters. Re-run it to apply your own values.",
        "info"
      );
    },
    [openState, pushToast]
  );

  return (
    <RiskStartDialog
      key={openKey ?? "no-run"}
      open={open}
      onOpenChange={handleOpenChange}
      candidates={candidates}
      initialScanId={openState?.scanJobId ?? null}
      deadlineSeconds={openState?.deadlineSeconds ?? null}
    />
  );
}
