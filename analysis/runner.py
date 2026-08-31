"""Analysis orchestration: start, execute and queue analysis runs.

Drives the four agent packages (CBOM -> Risk -> HNDL + MOSCA) against a
completed ScanJob's inventory and persists every stage onto an AnalysisRun
row. Follows the crypto_scan/pipeline.py discipline: DB rows are the source
of truth, the huey task is a thin async wrapper, and progress writes stay
idempotent.
"""

import logging
import os
import threading
from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from huey.contrib.djhuey import db_task

from cbom import CBOMAgent
from core.models import log_action
from core.modes import db_alias_for_mode
from discovery.models import NormalizedFinding, ScanJob
from hndl import HNDLAgent
from mosca_agent import MOSCAAgent
from risk_agent import RiskClassificationAgent

from .models import AnalysisRun, AssetAssessment
from .payload_builder import build_analysis_payload, default_raw_system_context, parse_finding_id

logger = logging.getLogger("analysis")


def start_analysis(scan_job, raw_system_context=None, max_findings: int = 500):
    """Create a queued AnalysisRun for a scan job and dispatch execution.

    Executes in-process via a daemon thread by default (plain runserver);
    ECDAT_QUEUE_ASYNC=1 routes through huey for a dedicated worker while
    immediate huey mode runs the task inline. Returns the created run.
    """
    db = scan_job._state.db or "default"
    max_findings = max_findings if max_findings is not None else 500
    payload = build_analysis_payload(scan_job, max_findings=max_findings)
    context = (
        raw_system_context
        if raw_system_context is not None
        else default_raw_system_context(scan_job)
    )
    run = AnalysisRun.objects.using(db).create(
        scan_job=scan_job,
        mode=scan_job.mode,
        status=AnalysisRun.Status.QUEUED,
        progress=0,
        repository=payload["repository"],
        raw_system_context=context,
        input_payload=payload,
        session_id=scan_job.session_id,
    )
    log_action(
        "analysis_started",
        f"Queued analysis for scan {scan_job.pk}",
        "analysisrun",
        run.pk,
        mode=scan_job.mode,
        session_id=run.session_id,
    )
    _dispatch(run, db)
    return run


def _context_timeout() -> int:
    """Seconds an auto-queued run waits for a context choice (default 30)."""
    raw = os.environ.get("ECDAT_AUTO_CONTEXT_TIMEOUT", "30")
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return 30


def _dispatch(run, db):
    """Run an already-queued AnalysisRun through the configured executor."""
    if os.environ.get("ECDAT_QUEUE_ASYNC") == "1":
        run_analysis_task(run.pk, run.mode)
    elif settings.HUEY.get("immediate"):
        run_analysis_task(run.pk, run.mode)
    else:
        threading.Thread(target=execute_analysis, args=(run.pk, run.mode), daemon=True).start()


def pending_analysis(scan_job, raw_system_context=None, max_findings: int = 500):
    """Create an awaiting-context AnalysisRun instead of dispatching it.

    The run is created with the (default) context and a deadline; once the
    user either picks a context (via ``continue_pending``) or the deadline
    passes untouched, it is queued and dispatched with whatever context was
    standing (default). Returns the created run.
    """
    db = scan_job._state.db or "default"
    max_findings = max_findings if max_findings is not None else 500
    payload = build_analysis_payload(scan_job, max_findings=max_findings)
    context = (
        raw_system_context
        if raw_system_context is not None
        else default_raw_system_context(scan_job)
    )
    timeout = _context_timeout()
    run = AnalysisRun.objects.using(db).create(
        scan_job=scan_job,
        mode=scan_job.mode,
        status=AnalysisRun.Status.AWAITING_CONTEXT,
        progress=0,
        repository=payload["repository"],
        raw_system_context=context,
        input_payload=payload,
        await_until=timezone.now() + timedelta(seconds=timeout) if timeout else None,
        session_id=scan_job.session_id,
    )
    log_action(
        "analysis_awaiting_context",
        f"Analysis for scan {scan_job.pk} awaits a context choice "
        f"(continuing with default in {timeout}s)",
        "analysisrun",
        run.pk,
        mode=scan_job.mode,
        session_id=run.session_id,
    )
    _schedule_auto_continue(run.pk, run.mode, db, timeout)
    return run


def _schedule_auto_continue(run_id, mode, db, timeout):
    if timeout and timeout > 0:
        threading.Thread(
            target=_auto_continue, args=(run_id, mode, db, timeout), daemon=True
        ).start()
    else:
        _auto_continue(run_id, mode, db, 0)


def _auto_continue(run_id, mode, db, timeout):
    """After `timeout` seconds, queue the awaiting run with its default context.

    Runs in a daemon thread so a closed/unresponsive page never blocks the
    workflow — the analysis simply continues with the default context. The
    AWAITING -> QUEUED transition is an atomic compare-and-swap so only one
    path (timer vs. the API redemption) ever dispatches the run.
    """
    from django.db import close_old_connections

    if timeout and timeout > 0:
        import time

        time.sleep(timeout)
    close_old_connections()
    try:
        run = AnalysisRun.objects.using(db).get(pk=run_id)
    except AnalysisRun.DoesNotExist:
        close_old_connections()
        return
    won = (
        AnalysisRun.objects.using(db)
        .filter(pk=run.pk, status=AnalysisRun.Status.AWAITING_CONTEXT)
        .update(
            status=AnalysisRun.Status.QUEUED,
            progress=0,
            await_until=None,
        )
    )
    if not won:
        close_old_connections()
        return
    run.status = AnalysisRun.Status.QUEUED
    run.progress = 0
    run.await_until = None
    log_action(
        "analysis_started",
        f"Auto-analysis continuing with default context for scan {run.scan_job_id}",
        "analysisrun",
        run.pk,
        mode=mode,
        session_id=run.session_id,
    )
    _dispatch(run, db)
    close_old_connections()


def continue_pending(run, raw_system_context=None, db=None, max_findings: int = 500):
    """Dispatch an awaiting-context run, optionally with a custom context.

    Replaces ``raw_system_context`` when given, flips the run to queued and
    starts execution. Raises ``ValueError`` if the run is no longer awaiting
    (the timeout already continued it) — callers must treat this as a
    duplicate-start signal, not a fresh failure.
    """
    db = db or run._state.db or "default"
    updates = {
        "status": AnalysisRun.Status.QUEUED,
        "progress": 0,
        "await_until": None,
    }
    if raw_system_context is not None:
        updates["raw_system_context"] = raw_system_context
    won = (
        AnalysisRun.objects.using(db)
        .filter(pk=run.pk, status=AnalysisRun.Status.AWAITING_CONTEXT)
        .update(**updates)
    )
    if not won:
        raise ValueError("Run is not awaiting a context choice.")
    run.status = AnalysisRun.Status.QUEUED
    run.progress = 0
    run.await_until = None
    if raw_system_context is not None:
        run.raw_system_context = raw_system_context
    log_action(
        "analysis_started",
        f"Analysis for scan {run.scan_job_id} started with {'custom' if raw_system_context is not None else 'default'} context",
        "analysisrun",
        run.pk,
        mode=run.mode,
        session_id=run.session_id,
    )
    _dispatch(run, db)
    return run


def execute_analysis(run_id, mode):
    """Run the full analysis pipeline synchronously and persist results.

    Never raises: any stage failure marks the run failed (with error text)
    and returns it. Returns None when the run row cannot be found. A run a
    user cancelled before execution starts is honoured (stays cancelled).
    """
    db = db_alias_for_mode(mode)
    try:
        run = AnalysisRun.objects.using(db).select_related("scan_job").get(pk=run_id)
    except AnalysisRun.DoesNotExist:
        logger.warning("execute_analysis: run %s not found in db '%s'", run_id, db)
        return None

    if run.status in (AnalysisRun.Status.CANCELLED, AnalysisRun.Status.COMPLETED):
        return run

    try:
        return _run_pipeline(run, db, mode)
    except Exception as exc:  # noqa: BLE001 - the run must be marked failed
        run.status = AnalysisRun.Status.FAILED
        run.progress = 0
        run.error = str(exc)
        run.finished_at = timezone.now()
        run.save(using=db, update_fields=["status", "progress", "error", "finished_at"])
        log_action("system", f"Analysis failed: {exc}", "analysisrun", run.pk, mode=mode,
                   session_id=run.session_id)
        return run


def _run_is_cancelled(run, db) -> bool:
    """True once the run row has been flipped to cancelled (by any request)."""
    return (
        AnalysisRun.objects.using(db)
        .filter(pk=run.pk, status=AnalysisRun.Status.CANCELLED)
        .exists()
    )


def _mark_cancelled(run, db) -> None:
    """Persist the cancelled state for a run the caller has already CAS'd."""
    run.status = AnalysisRun.Status.CANCELLED
    run.progress = 0
    run.error = "Cancelled by user"
    run.finished_at = timezone.now()
    run.await_until = None
    run.save(using=db, update_fields=["status", "progress", "error", "finished_at", "await_until"])
    log_action("analysis_cancelled", "Analysis run cancelled by user",
               "analysisrun", run.pk, mode=run.mode, session_id=run.session_id)


def cancel_run(run, db=None) -> bool:
    """Cancel an analysis run (compare-and-swap) and return True if it won.

    Cancellable states: awaiting_context, queued, running. No-op (False) for
    completed/failed/cancelled runs. The running worker thread stops at the
    next interrupt check; the awaiting-context auto-continue timer loses the
    CAS and never dispatches.
    """
    db = db or run._state.db or "default"
    won = (
        AnalysisRun.objects.using(db)
        .filter(
            pk=run.pk,
            status__in=[
                AnalysisRun.Status.AWAITING_CONTEXT,
                AnalysisRun.Status.QUEUED,
                AnalysisRun.Status.RUNNING,
            ],
        )
        .update(
            status=AnalysisRun.Status.CANCELLED,
            progress=0,
            error="Cancelled by user",
            finished_at=timezone.now(),
            await_until=None,
        )
    )
    if not won:
        return False
    _mark_cancelled(run, db)
    return True


def _run_pipeline(run, db, mode):
    """Execute the five-stage analysis pipeline on an already-loaded run.

    The queued->running transition is a compare-and-swap so a cancelled or
    already-owned run is never started twice; cancellation is honoured
    between asset assessments so a mid-analysis cancel lands promptly.
    """
    won = (
        AnalysisRun.objects.using(db)
        .filter(pk=run.pk, status=AnalysisRun.Status.QUEUED)
        .update(status=AnalysisRun.Status.RUNNING, progress=5, started_at=timezone.now())
    )
    if not won:
        # Either someone else owns it, or the user cancelled it first.
        return run
    run.status = AnalysisRun.Status.RUNNING
    run.progress = 5
    run.started_at = timezone.now()

    payload = run.input_payload or {}
    if not payload:
        scan_job = ScanJob.objects.using(db).get(pk=run.scan_job_id)
        payload = build_analysis_payload(scan_job)

    cbom = CBOMAgent().process(payload)
    run.cbom_document = cbom
    run.progress = 35
    run.save(using=db, update_fields=["cbom_document", "progress"])

    risk_ctx = RiskClassificationAgent().analyze(run.raw_system_context)
    run.risk_context = risk_ctx
    run.progress = 45
    run.save(using=db, update_fields=["risk_context", "progress"])

    hndl = HNDLAgent()
    mosca = MOSCAAgent(verbose=False)
    assets = cbom.get("crypto_assets") or []
    total = max(1, len(assets))
    rows = []
    urgent = 0
    critical = 0
    hndl_applicable = 0

    for i, asset in enumerate(assets):
        if _run_is_cancelled(run, db):
            _mark_cancelled(run, db)
            return run
        if not isinstance(asset, dict):
            continue
        h_res = hndl.analyze(cbom_asset=asset, risk_context=risk_ctx)
        m_res = mosca.analyze(asset)

        asset_obj = None
        pk = parse_finding_id(asset.get("asset_id"))
        if pk is not None:
            try:
                norm = NormalizedFinding.objects.using(db).get(pk=pk)
            except NormalizedFinding.DoesNotExist:
                norm = None
            if norm is not None:
                asset_obj = norm.assets.first()
                if asset_obj is not None:
                    _write_back_parameters(asset, asset_obj, db)

        AssetAssessment.objects.using(db).create(
            run=run,
            mode=mode,
            asset=asset_obj,
            finding_ref=str(asset.get("asset_id") or ""),
            cbom_asset=asset,
            hndl_result=h_res,
            mosca_result=m_res,
            session_id=run.session_id,
        )

        m_assessment = m_res.get("mosca_assessment") or {}
        h_body = h_res.get("hndl") or {}
        rows.append(
            {
                "asset_id": asset.get("asset_id"),
                "algorithm": asset.get("algorithm", ""),
                "algorithm_category": m_assessment.get("algorithm_category", ""),
                "classical_security": m_assessment.get("classical_security", ""),
                "hndl_risk": h_body.get("future_decryption_risk", ""),
                "overall_risk": m_assessment.get("overall_risk", ""),
                "migration_priority": m_assessment.get("migration_priority", ""),
                "quantum_vulnerable": m_assessment.get("quantum_vulnerable"),
            }
        )
        if m_assessment.get("migration_priority") == "URGENT":
            urgent += 1
        if m_assessment.get("overall_risk") == "CRITICAL":
            critical += 1
        if h_body.get("applicable"):
            hndl_applicable += 1

        run.progress = 50 + int(45 * (i + 1) / total)
        run.save(using=db, update_fields=["progress"])

    # Honour a cancel that landed between the last assessment and completion.
    if _run_is_cancelled(run, db):
        _mark_cancelled(run, db)
        return run

    run.executive_summary = {
        "rows": rows,
        "stats": {
            "assets": len(assets),
            "urgent": urgent,
            "critical": critical,
            "hndl_applicable": hndl_applicable,
        },
    }
    run.status = AnalysisRun.Status.COMPLETED
    run.progress = 100
    run.finished_at = timezone.now()
    run.save(using=db, update_fields=["executive_summary", "status", "progress", "finished_at"])
    log_action(
        "analysis_completed",
        f"Analysis complete: {len(assets)} assets assessed",
        "analysisrun",
        run.pk,
        mode=mode,
        session_id=run.session_id,
    )
    _auto_mitigation(run, db)
    return run


def _auto_mitigation(run, db):
    """Auto-pass a completed analysis into the mitigation planner.

    Off by default only when ECDAT_MITIGATION_OFF is set; the plan generation
    runs through the planner's own dispatch (daemon thread / huey) so it never
    blocks analysis completion.
    """
    if os.environ.get("ECDAT_MITIGATION_OFF", "").lower() in ("1", "true"):
        return
    try:
        from mitigation.planner import trigger_mitigation

        trigger_mitigation(run, db)
    except Exception as exc:  # noqa: BLE001 - never break a completed run
        logger.warning("_auto_mitigation: could not queue mitigation for run %s: %s", run.pk, exc)


def _write_back_parameters(asset, asset_obj, db):
    """Backfill discovery CryptoAsset parameters from CBOM-extracted ones."""
    params = asset.get("parameters") or {}
    updates = {}
    if params.get("key_size") is not None and asset_obj.key_size is None:
        updates["key_size"] = params["key_size"]
    if params.get("curve") and not asset_obj.curve:
        updates["curve"] = params["curve"]
    if updates:
        for field, value in updates.items():
            setattr(asset_obj, field, value)
        asset_obj.save(using=db, update_fields=list(updates))


@db_task()
def run_analysis_task(run_id, mode):
    """Thin huey task wrapper around execute_analysis; never crashes the worker."""
    try:
        execute_analysis(run_id, mode)
    except Exception as exc:  # noqa: BLE001 - worker must survive unexpected errors
        logger.exception("run_analysis_task: analysis %s (mode=%s) crashed: %s", run_id, mode, exc)


def sweep_pending_runs() -> int:
    """Re-queue analysis runs a previous process left unfinished.

    Startup recovery (run_all.sh / run_huey boot):
      - QUEUED runs a previous process never started are re-dispatched.
      - RUNNING runs stuck midway (process died) have their partial
        assessments dropped and restart clean from the top.
      - AWAITING_CONTEXT runs whose deadline passed continue with the
        default context (the in-process timer died with the old process).

    New work is enqueued on the huey queue (persistent between processes) so
    the worker that `run_all.sh` starts completes it. Returns the count of
    runs re-queued.
    """
    from core import modes as modes_mod

    recovered = 0
    for mode in modes_mod.MODES:
        db = modes_mod.db_alias_for_mode(mode)

        for run in list(
            AnalysisRun.objects.using(db).filter(status=AnalysisRun.Status.QUEUED)[:200]
        ):
            log_action("analysis_requeued", f"Re-queued stuck analysis {run.pk} to complete it",
                       "analysisrun", run.pk, mode=mode, session_id=run.session_id)
            run_analysis_task(run.pk, run.mode)
            recovered += 1

        for run in list(
            AnalysisRun.objects.using(db).filter(status=AnalysisRun.Status.RUNNING)[:200]
        ):
            AssetAssessment.objects.using(db).filter(run=run).delete()
            run.status = AnalysisRun.Status.QUEUED
            run.progress = 0
            run.error = ""
            run.save(using=db, update_fields=["status", "progress", "error"])
            log_action("analysis_requeued", f"Restarted stuck analysis {run.pk} to complete it",
                       "analysisrun", run.pk, mode=mode, session_id=run.session_id)
            run_analysis_task(run.pk, run.mode)
            recovered += 1

        overdue = list(
            AnalysisRun.objects.using(db).filter(
                status=AnalysisRun.Status.AWAITING_CONTEXT,
                await_until__isnull=False,
                await_until__lte=timezone.now(),
            )[:50]
        )
        for run in overdue:
            _auto_continue(run.pk, run.mode, db, 0)
            recovered += 1

    return recovered