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

from segments.ml.cbom import CBOMAgent
from segments.ml.cbom.ai_provider import FallbackLLMProvider
from core.models import log_action
from core.modes import active_mode, db_alias_for_mode
from segments.scraping.discovery.models import NormalizedFinding, ScanJob
from segments.ml.hndl import HNDLAgent
from segments.ml.mosca_agent import MOSCAAgent
from segments.ml.risk_agent import RiskClassificationAgent

from .models import AnalysisRun, AssetAssessment
from .payload_builder import build_analysis_payload, default_raw_system_context, parse_finding_id

logger = logging.getLogger("analysis")


def start_analysis(scan_job, raw_system_context=None, max_findings: int | None = None):
    """Create a queued AnalysisRun for a scan job and dispatch execution.

    Executes in-process via a daemon thread by default (plain runserver);
    ECDAT_QUEUE_ASYNC=1 routes through huey for a dedicated worker while
    immediate huey mode runs the task inline. Returns the created run.

    `max_findings=None` analyses every discovered finding; pass an int to cap it.
    """
    db = scan_job._state.db or "default"
    payload = build_analysis_payload(scan_job, max_findings=max_findings)
    context = (
        raw_system_context
        if raw_system_context is not None
        else default_raw_system_context(scan_job)
    )
    run = AnalysisRun.objects.using(db).create(
        scan_job=scan_job,
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
        session_id=run.session_id,
    )
    _dispatch(run, db)
    return run


def _context_timeout() -> int:
    """Seconds a parked run waits for the operator to supply context.

    Defaults to 60: long enough to answer the MOSCA/HNDL form, short enough
    that an unattended run still reaches a result on its own with the
    conservative defaults rather than sitting in AWAITING_CONTEXT forever.
    Override with ECDAT_AUTO_CONTEXT_TIMEOUT.
    """
    raw = os.environ.get("ECDAT_AUTO_CONTEXT_TIMEOUT", "60")
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return 60


def _dispatch(run, db):
    """Run an already-queued AnalysisRun through the configured executor."""
    if os.environ.get("ECDAT_QUEUE_ASYNC") == "1":
        run_analysis_task(run.pk, active_mode())
    elif settings.HUEY.get("immediate"):
        run_analysis_task(run.pk, active_mode())
    else:
        threading.Thread(target=execute_analysis, args=(run.pk, active_mode()), daemon=True).start()


def pending_analysis(scan_job, raw_system_context=None, max_findings: int | None = None):
    """Create an awaiting-context AnalysisRun instead of dispatching it.

    The run is created with the (default) context and a deadline; once the
    user either picks a context (via ``continue_pending``) or the deadline
    passes untouched, it is queued and dispatched with whatever context was
    standing (default). Returns the created run.

    `max_findings=None` analyses every discovered finding; pass an int to cap it.
    """
    db = scan_job._state.db or "default"
    payload = build_analysis_payload(scan_job, max_findings=max_findings)
    context = (
        raw_system_context
        if raw_system_context is not None
        else default_raw_system_context(scan_job)
    )
    timeout = _context_timeout()
    run = AnalysisRun.objects.using(db).create(
        scan_job=scan_job,
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
        session_id=run.session_id,
    )
    _schedule_auto_continue(run.pk, active_mode(), db, timeout)
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
        session_id=run.session_id,
    )
    _dispatch(run, db)
    close_old_connections()


def continue_pending(run, raw_system_context=None, db=None, max_findings: int | None = None):
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

        if run.status in (
            AnalysisRun.Status.CANCELLED,
            AnalysisRun.Status.COMPLETED,
            # A paused run must not be picked up by a stray sweep or a second
            # dispatch; only resume_run() may move it back to queued.
            AnalysisRun.Status.PAUSED,
        ):
            return run


    try:
        return _run_pipeline(run, db, mode)
    except Exception as exc:  # noqa: BLE001 - the run must be marked failed
        run.status = AnalysisRun.Status.FAILED
        run.progress = 0
        run.error = str(exc)
        run.finished_at = timezone.now()
        run.save(using=db, update_fields=["status", "progress", "error", "finished_at"])
        log_action("system", f"Analysis failed: {exc}", "analysisrun", run.pk,
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
               "analysisrun", run.pk, session_id=run.session_id)


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


def _run_is_paused(run, db) -> bool:
    """True once the operator has paused the run."""
    return AnalysisRun.objects.using(db).filter(pk=run.pk, status=AnalysisRun.Status.PAUSED).exists()


def _mark_paused(run, db) -> None:
    """Park a run the operator paused, keeping the progress it reached."""
    AnalysisRun.objects.using(db).filter(pk=run.pk).update(
        status=AnalysisRun.Status.PAUSED,
        await_until=None,
    )
    run.status = AnalysisRun.Status.PAUSED


def pause_run(run, db=None) -> bool:
    """Pause a running analysis (compare-and-swap). Returns True if it won.

    Pausable states are the same as cancellable ones minus the terminal ones, so
    a pause is always something the operator can undo by resuming. The worker
    thread stops at its next asset checkpoint; assessments already written stay.
    """
    db = db or run._state.db or "default"
    won = (
        AnalysisRun.objects.using(db)
        .filter(
            pk=run.pk,
            status__in=[AnalysisRun.Status.QUEUED, AnalysisRun.Status.RUNNING],
        )
        .update(
            status=AnalysisRun.Status.PAUSED,
            await_until=None,
            finished_at=None,
        )
    )
    if won:
        run.status = AnalysisRun.Status.PAUSED
        log_action(
            "analysis_paused",
            f"Analysis run {run.pk} paused by user",
            "analysisrun",
            run.pk,
            session_id=run.session_id,
        )
    return bool(won)


def resume_run(run, db=None) -> bool:
    """Resume a paused analysis by re-queueing and re-dispatching it.

    The pipeline is re-entered from the start, but assets that already have an
    ``AssetAssessment`` for this run are skipped, so pausing is cheap rather than
    a restart. Those assessments are written inside the per-asset loop, which is
    also where the pause is honoured, so nothing completed is ever redone.
    """
    db = db or run._state.db or "default"
    won = (
        AnalysisRun.objects.using(db)
        .filter(pk=run.pk, status=AnalysisRun.Status.PAUSED)
        .update(
            status=AnalysisRun.Status.QUEUED,
            progress=0,
            error="",
            finished_at=None,
            await_until=None,
        )
    )
    if won:
        run.status = AnalysisRun.Status.QUEUED
        run.progress = 0
        run.error = ""
        log_action(
            "analysis_resumed",
            f"Analysis run {run.pk} resumed by user",
            "analysisrun",
            run.pk,
            session_id=run.session_id,
        )
        _dispatch(run, db)
    return bool(won)


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

    cbom = CBOMAgent(llm_provider=FallbackLLMProvider()).process(payload)
    run.cbom_document = cbom
    run.progress = 35
    run.save(using=db, update_fields=["cbom_document", "progress"])

    from segments.ml.cbom.threat_context import resolve_threat_context
    threat_ctx = resolve_threat_context(run.raw_system_context)

    risk_ctx = RiskClassificationAgent().analyze(run.raw_system_context)
    risk_ctx["data_lifetime_years"] = threat_ctx.data_shelf_life_y
    risk_ctx["migration_time_years"] = threat_ctx.migration_years_x
    risk_ctx["quantum_horizon_year"] = threat_ctx.crqc_year_z
    risk_ctx["assessment_year"] = threat_ctx.assessment_year
    risk_ctx["network_exposure"] = threat_ctx.network_exposure
    risk_ctx["internet_exposed"] = threat_ctx.internet_facing
    risk_ctx["standards_profile"] = threat_ctx.standards_profile
    risk_ctx["data_sensitivity"] = threat_ctx.data_sensitivity
    risk_ctx["data_types"] = threat_ctx.data_types
    risk_ctx["hndl_assessable"] = threat_ctx.hndl_assessable
    run.risk_context = risk_ctx
    run.progress = 45
    run.save(using=db, update_fields=["risk_context", "progress"])

    hndl = HNDLAgent(
        default_quantum_horizon_year=threat_ctx.crqc_year_z,
        default_assessment_year=threat_ctx.assessment_year,
    )
    mosca = MOSCAAgent(
        verbose=False,
        default_quantum_horizon_year=threat_ctx.crqc_year_z,
        default_assessment_year=threat_ctx.assessment_year,
    )
    assets = cbom.get("crypto_assets") or []
    total = max(1, len(assets))
    rows = []
    urgent = 0
    critical = 0
    hndl_applicable = 0

    # Resume support. Each asset writes its AssetAssessment inside the loop
    # below, so on a resumed run the ones already done can be skipped and their
    # contribution to the summary rebuilt from the stored rows. Without this a
    # resume would silently re-assess everything and double-count.
    resumed = (
        AssetAssessment.objects.using(db)
        .filter(run=run)
        .exclude(finding_ref="")
        .order_by("id")
    )
    done_refs = set()
    for existing in resumed:
        m = (existing.mosca_result or {}).get("mosca_assessment") or {}
        h = (existing.hndl_result or {}).get("hndl") or {}
        ref = str(existing.finding_ref)
        done_refs.add(ref)
        pri = str(m.get("migration_priority") or "").upper()
        risk = str(m.get("overall_risk") or "").upper()
        h_risk = h.get("future_decryption_risk", "")
        cb = existing.cbom_asset or {}
        if (not h_risk or h_risk in ("NOT_ASSESSABLE", "UNKNOWN")) and cb.get("hndl_exposure"):
            h_risk = str(cb.get("hndl_exposure")).upper()
        rows.append(
            {
                "asset_id": ref,
                "algorithm": (cb.get("algorithm") or ""),
                "algorithm_category": m.get("algorithm_category", ""),
                "classical_security": m.get("classical_security", ""),
                "hndl_risk": h_risk,
                "overall_risk": m.get("overall_risk", ""),
                "migration_priority": m.get("migration_priority", ""),
                "quantum_vulnerable": m.get("quantum_vulnerable"),
            }
        )
        if pri in ("URGENT", "CRITICAL") or risk == "URGENT":
            urgent += 1
        if risk in ("CRITICAL", "HIGH", "URGENT") or pri in ("URGENT", "CRITICAL"):
            critical += 1
        if h.get("applicable") or h_risk in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            hndl_applicable += 1
    if done_refs:
        logger.info(
            "Analysis %s resuming: %d of %d assets already assessed", run.pk, len(done_refs), len(assets)
        )

    for i, asset in enumerate(assets):
        if _run_is_cancelled(run, db):
            _mark_cancelled(run, db)
            return run
        # Pause lands on the same asset boundary as cancel, so a pause costs at
        # most one asset of work rather than the whole run.
        if _run_is_paused(run, db):
            _mark_paused(run, db)
            log_action(
                "analysis_paused",
                f"Analysis run {run.pk} paused after {len(rows)} of {len(assets)} assets",
                "analysisrun",
                run.pk,
                session_id=run.session_id,
            )
            return run
        if not isinstance(asset, dict):
            continue
        # Already assessed on an earlier (resumed) pass.
        if str(asset.get("asset_id") or "") in done_refs:
            continue
        h_res = hndl.analyze(
            cbom_asset=asset,
            risk_context=risk_ctx,
            quantum_horizon_year=threat_ctx.crqc_year_z,
            assessment_year=threat_ctx.assessment_year,
        )
        m_res = mosca.analyze(
            asset,
            operational_context=risk_ctx,
            quantum_horizon_year=threat_ctx.crqc_year_z,
            assessment_year=threat_ctx.assessment_year,
        )

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

        m_assessment = m_res.get("mosca_assessment") or {}
        h_body = h_res.get("hndl") or {}
        algo_name = str(asset.get("algorithm") or asset.get("name") or "").upper()
        fam = str(asset.get("family") or "").lower()

        # Authoritative Deterministic Classification
        from segments.ml.risk_classifier import classify_canonical_asset

        hndl_risk_val = h_body.get("future_decryption_risk") or asset.get("hndl_exposure") or ""
        mosca_params = m_assessment.get("mosca_parameters") or {}
        mosca_def_val = m_assessment.get("timeline_deficit_years") or mosca_params.get("deficit_margin")

        classification_input = {
            "algorithm": algo_name,
            "family": fam,
            "key_size": (asset.get("parameters") or {}).get("key_size") or asset.get("key_size"),
            "role": asset.get("role") or asset.get("purpose") or m_assessment.get("algorithm_category"),
            "network_exposure": asset.get("network_exposure") or asset.get("exposure") or threat_ctx.network_exposure,
            "internet_facing": bool(
                asset.get("internet_facing")
                or asset.get("public_endpoint")
                or threat_ctx.internet_facing
                or threat_ctx.network_exposure in ("public", "external")
            ),
            "hndl_risk": hndl_risk_val,
            "migration_time_years": asset.get("migration_time_years") or mosca_params.get("x_migration_time"),
            "data_shelf_life_years": asset.get("data_shelf_life_years") or mosca_params.get("y_shelf_life"),
            "quantum_horizon_years": threat_ctx.crqc_year_z,
            "mosca_at_risk": threat_ctx.mosca_at_risk or (float(mosca_def_val) > 0 if mosca_def_val is not None else False),
            "mosca_status": m_assessment.get("mosca_status"),
            "exploitability_score": asset.get("exploitability_score"),
        }
        cls_res = classify_canonical_asset(classification_input)

        m_assessment["migration_priority"] = cls_res["priority"]
        m_assessment["overall_risk"] = cls_res["risk_tier"]
        m_assessment["remediation_wave"] = cls_res["remediation_wave"]
        m_assessment["urgency_reason"] = cls_res["urgency_reason"]
        m_assessment["classical_security"] = cls_res["classical_security"]

        AssetAssessment.objects.using(db).create(
            run=run,
            asset=asset_obj,
            finding_ref=str(asset.get("asset_id") or ""),
            cbom_asset=asset,
            hndl_result=h_res,
            mosca_result=m_res,
            session_id=run.session_id,
        )

        hndl_risk_final = cls_res.get("hndl_exposure") or h_body.get("future_decryption_risk", "")
        if (not hndl_risk_final or hndl_risk_final in ("NOT_ASSESSABLE", "UNKNOWN")) and asset.get("hndl_exposure"):
            hndl_risk_final = str(asset.get("hndl_exposure")).upper()

        rows.append(
            {
                "asset_id": asset.get("asset_id"),
                "algorithm": asset.get("algorithm", ""),
                "algorithm_category": m_assessment.get("algorithm_category", ""),
                "classical_security": cls_res.get("classical_security") or m_assessment.get("classical_security", ""),
                "hndl_risk": hndl_risk_final,
                "overall_risk": cls_res.get("risk_tier") or m_assessment.get("overall_risk", ""),
                "migration_priority": cls_res.get("priority") or m_assessment.get("migration_priority", ""),
                "quantum_vulnerable": cls_res.get("quantum_vulnerable") if cls_res.get("quantum_vulnerable") is not None else m_assessment.get("quantum_vulnerable"),
            }
        )
        pri = str(cls_res.get("priority") or m_assessment.get("migration_priority") or "").upper()
        risk = str(cls_res.get("risk_tier") or m_assessment.get("overall_risk") or "").upper()
        if pri in ("URGENT", "CRITICAL") or risk == "URGENT":
            urgent += 1
        if risk in ("CRITICAL", "HIGH", "URGENT") or pri in ("URGENT", "CRITICAL"):
            critical += 1
        if h_body.get("applicable") or hndl_risk_final in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            hndl_applicable += 1

        run.progress = 50 + int(45 * (i + 1) / total)
        run.save(using=db, update_fields=["progress"])

    # Honour a cancel that landed between the last assessment and completion.
    if _run_is_cancelled(run, db):
        _mark_cancelled(run, db)
        return run

    # Aggregate distinct algorithm categories
    cats = list({str(r.get("algorithm_category")).upper() for r in rows if r.get("algorithm_category") and r.get("algorithm_category") != "UNKNOWN"})
    primary_category = " / ".join(sorted(cats)) if cats else "PUBLIC_KEY"

    run.executive_summary = {
        "algorithm_category": primary_category,
        "rows": rows,
        "stats": {
            "assets": len(assets),
            "urgent": urgent,
            "critical": critical,
            "hndl_applicable": hndl_applicable,
        },
        "threat_context": {
            "migration_years_x": threat_ctx.migration_years_x,
            "data_shelf_life_y": threat_ctx.data_shelf_life_y,
            "crqc_year_z": threat_ctx.crqc_year_z,
            "years_until_crqc": threat_ctx.years_until_crqc,
            "mosca_at_risk": threat_ctx.mosca_at_risk,
            "network_exposure": threat_ctx.network_exposure,
            "standards_profile": threat_ctx.standards_profile,
            "conflict_warnings": threat_ctx.conflict_warnings,
            "hndl_assessable": threat_ctx.hndl_assessable,
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
        from segments.mitigation.mitigation.planner import trigger_mitigation

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
        logger.exception("run_analysis_task: analysis %s crashed: %s", run_id, exc)


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
                       "analysisrun", run.pk, session_id=run.session_id)
            run_analysis_task(run.pk, active_mode())
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
                       "analysisrun", run.pk, session_id=run.session_id)
            run_analysis_task(run.pk, active_mode())
            recovered += 1

        overdue = list(
            AnalysisRun.objects.using(db).filter(
                status=AnalysisRun.Status.AWAITING_CONTEXT,
                await_until__isnull=False,
                await_until__lte=timezone.now(),
            )[:50]
        )
        for run in overdue:
            _auto_continue(run.pk, active_mode(), db, 0)
            recovered += 1

    return recovered