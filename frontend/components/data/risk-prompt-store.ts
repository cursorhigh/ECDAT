"use client";

/**
 * Single-owner registry for the operational-context modal.
 *
 * `RiskStartDialog` used to be mounted on the assets page, the scans page *and*
 * the global prompt. Each mount was independent, so the same parked run could be
 * shown twice at once -- which is exactly the "it asks me twice" symptom. The
 * dedupe set below was only consulted by the assets page, so the other two mounts
 * never registered and the global prompt fired alongside them.
 *
 * The durable fix is structural rather than bookkeeping: the dialog is now
 * mounted exactly once, in `RiskContextPrompt`, and the pages that want it to
 * appear ask for it here instead of rendering their own copy.
 */

/** Runs whose modal has already been put in front of the operator. */
const surfaced = new Set<number>();

/**
 * Why the modal is being opened.
 *
 * `start` is a deliberate button press: nobody asked for it, so there is no
 * deadline and nothing should start ticking. The operator is filling the form
 * in and the run is created only when they submit.
 *
 * `resume` is a run the backend already parked at AWAITING_CONTEXT, either
 * because discovery finished and auto-staged the assessment, or because a page
 * is answering one that is already waiting. A server deadline is running, so
 * the countdown is shown and the form locks when it lapses.
 */
export type RiskPromptKind = "start" | "resume";

export interface RiskPromptRequest {
  kind: RiskPromptKind;
  scanJobId: number;
  /** Only meaningful for `resume`: the seconds the server has left. */
  deadlineSeconds?: number | null;
}

type Listener = (request: RiskPromptRequest) => void;

let listener: Listener | null = null;

/** Called when a run's context modal has been shown. */
export function markRiskPromptSurfaced(runId: number): void {
  surfaced.add(runId);
}

export function isRiskPromptSurfaced(runId: number): boolean {
  return surfaced.has(runId);
}

/**
 * Drop a run once it is no longer awaiting, so the set cannot grow without bound
 * over a long session.
 */
export function forgetRiskPrompt(runId: number): void {
  surfaced.delete(runId);
}

/**
 * Subscribe the single mounted prompt to explicit open requests.
 *
 * Returns an unsubscribe function. Only one listener is ever held: a second
 * subscriber would itself be a second way for two dialogs to appear, so a new
 * subscriber replaces the old one.
 */
export function onRiskPromptRequest(handler: Listener): () => void {
  listener = handler;
  return () => {
    if (listener === handler) listener = null;
  };
}

/** Ask the mounted prompt to open. A no-op if the prompt is not mounted. */
export function requestRiskPrompt(request: RiskPromptRequest): void {
  listener?.(request);
}
