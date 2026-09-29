"""Function views for the analysis app (API endpoints)."""

import json

from django.db.models import Count
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from core.api import require_scan_scope
from core.modes import active_db, active_mode, db_alias_for_mode
from core.sessions import scope, thread_session_id
from segments.scraping.discovery.models import ScanJob

from .models import AnalysisRun, AssetAssessment
from .runner import (
    _auto_continue,
    _context_timeout,
    cancel_run,
    continue_pending,
    pause_run,
    resume_run,
    pending_analysis,
    start_analysis,
)


_PRIORITY_RANK = {"URGENT": 0, "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _priority_rank(value):
    """Rank a migration-priority / overall-risk label (lower = more urgent)."""
    if not value:
        return 99
    return _PRIORITY_RANK.get(str(value).upper(), 50)


def _load_run(run_id):
    """Return (run, db) for a run.

    There is one database, so this is a single lookup. It previously fell
    back to the *other* mode's database when a run was not in the active one,
    which is meaningless now: the fallback queried the same alias and then
    re-queried it a third time, so a genuine "not found" cost two extra
    round trips before raising.
    """
    db = active_db()
    run = AnalysisRun.objects.using(db).select_related("scan_job").get(pk=run_id)
    return run, db


def _assessment_summary(a):
    asset = a.asset
    return {
        "id": a.pk,
        "finding_ref": a.finding_ref,
        "asset_id": a.asset_id if a.asset_id is not None else a.cbom_asset.get("asset_id"),
        "asset_name": asset.name if asset else "",
        "asset_family": asset.family if asset else "",
        "cbom_asset": a.cbom_asset,
        "hndl": a.hndl_result,
        "mosca": a.mosca_result,
    }


@csrf_exempt
def analysis_list(request):
    """List recent analysis runs (GET /api/analysis/)."""
    if request.method != "GET":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    db = active_db()
    runs = (
        scope(AnalysisRun.objects.using(db), thread_session_id())
        .select_related("scan_job")
        .annotate(assets_count=Count("assessments"))
        .order_by("-created_at")[:50]
    )
    return JsonResponse(
        [
            {
                "id": r.pk,
                "scan_job_id": r.scan_job_id,
                "target": r.scan_job.target,
                "status": r.status,
                "progress": r.progress,
                "created_at": r.created_at,
                "assets": r.assets_count,
            }
            for r in runs
        ],
        safe=False,
    )


@require_GET
def analysis_awaiting(request):
    """List runs waiting on a context choice (GET /api/analysis/awaiting/).

    Used by the dashboard popup: when an auto-queued analysis is paused
    waiting for the user to pick between the default context and a modified
    one, this returns the pending run(s) with the remaining seconds.
    """
    db = active_db()
    now = timezone.now()
    runs = (
        scope(AnalysisRun.objects.using(db), thread_session_id())
        .filter(status=AnalysisRun.Status.AWAITING_CONTEXT)
        .select_related("scan_job")
        .order_by("-created_at")
    )
    rows = []
    for r in runs[:5]:
        # The fallback timer may have missed its deadline (server restart while
        # it slept); a run past `await_until` continues with the default now.
        if r.await_until and r.await_until <= now:
            _auto_continue(r.pk, active_mode(), db, 0)
            continue
        seconds_left = 0
        if r.await_until:
            seconds_left = max(0, int((r.await_until - now).total_seconds()))
        rows.append(
            {
                "id": r.pk,
                "scan_job_id": r.scan_job_id,
                "target": r.scan_job.target,
                "session_id": r.session_id,
                "created_at": r.created_at,
                "seconds_left": seconds_left,
            }
        )
    return JsonResponse(rows, safe=False)


@csrf_exempt
@require_POST
def analysis_start(request):
    """Queue an analysis run for a completed scan job (POST /api/analysis/start/).

    A scan that already has an awaiting-context run re-uses that run -- the
    passed ``raw_system_context`` (or the default) is what gets committed and
    dispatched, so the manual form and the auto-analysis prompt resolve to the
    same row instead of duplicating runs.
    """
    try:
        payload = json.loads(request.body or b"{}")
    except ValueError:
        return JsonResponse({"detail": "Invalid JSON body"}, status=400)

    scan_job_id = payload.get("scan_job")
    if not scan_job_id:
        return JsonResponse({"detail": "Missing required field `scan_job`."}, status=400)

    db = active_db()
    try:
        scan_job = ScanJob.objects.using(db).get(pk=scan_job_id)
    except ScanJob.DoesNotExist:
        return JsonResponse({"detail": f"Scan job {scan_job_id} not found."}, status=400)

    if scan_job.status != ScanJob.Status.COMPLETED:
        return JsonResponse(
            {
                "detail": (
                    f"Scan job {scan_job_id} is {scan_job.status}; "
                    "only completed scans can be analyzed."
                )
            },
            status=400,
        )

    # No artificial cap. `max_findings` is optional and an absent value means
    # "analyse every discovered finding"; a caller that does pass one still gets
    # its number honoured. The only rejection is a non-positive count, which
    # would silently produce an empty assessment.
    max_findings = payload.get("max_findings")
    if max_findings is not None:
        try:
            max_findings = int(max_findings)
        except (TypeError, ValueError):
            return JsonResponse(
                {"detail": "`max_findings` must be a positive integer."},
                status=400,
            )
        if max_findings < 1:
            return JsonResponse(
                {"detail": "`max_findings` must be a positive integer."},
                status=400,
            )

    raw_context = payload.get("raw_system_context")
    # `defer` starts the run but parks it in AWAITING_CONTEXT instead of
    # dispatching it, so the user is prompted for MOSCA/HNDL parameters while
    # the run already exists. If they never answer, the deadline created by
    # `pending_analysis` queues it with the conservative defaults. The frontend
    # sends this when the button is pressed, and follows up with the user's
    # answers as a second call, which lands on the same run.
    defer = bool(payload.get("defer"))
    existing = (
        scope(AnalysisRun.objects.using(db), thread_session_id())
        .filter(scan_job=scan_job, status=AnalysisRun.Status.AWAITING_CONTEXT)
        .order_by("-created_at")
        .first()
    )
    if existing is not None:
        try:
            run = continue_pending(existing, raw_context, db=db, max_findings=max_findings)
        except ValueError:
            return JsonResponse(
                {"detail": "This scan's analysis has already been queued."}, status=409
            )
        return JsonResponse(
            {
                "id": run.pk,
                "scan_job_id": run.scan_job_id,
                "status": run.status,
                "progress": run.progress,
                "created_at": run.created_at,
                "assets": 0,
                "context_deadline_seconds": _context_timeout() if run.status == AnalysisRun.Status.AWAITING_CONTEXT else 0,
            },
            status=200,
        )

    # No awaiting run: the context timer may already have queued it. Reuse the
    # active run instead of starting a duplicate (and apply a queued run's
    # custom context before it executes, if handed one).
    active = (
        scope(AnalysisRun.objects.using(db), thread_session_id())
        .filter(
            scan_job=scan_job,
            status__in=[
                AnalysisRun.Status.AWAITING_CONTEXT,
                AnalysisRun.Status.QUEUED,
                AnalysisRun.Status.RUNNING,
            ],
        )
        .order_by("-created_at")
        .first()
    )
    if active is not None:
        if raw_context is not None and active.status == AnalysisRun.Status.QUEUED:
            active.raw_system_context = raw_context
            active.save(using=db, update_fields=["raw_system_context"])
            active.refresh_from_db()
        return JsonResponse(
            {
                "id": active.pk,
                "scan_job_id": active.scan_job_id,
                "status": active.status,
                "progress": active.progress,
                "created_at": active.created_at,
                "assets": 0,
            "context_deadline_seconds": _context_timeout() if active.status == AnalysisRun.Status.AWAITING_CONTEXT else 0,
            },
            status=200,
        )

    if defer:
        run = pending_analysis(scan_job, raw_context, max_findings=max_findings)
        return JsonResponse(
            {
                "id": run.pk,
                "scan_job_id": run.scan_job_id,
                "status": run.status,
                "progress": run.progress,
                "created_at": run.created_at,
                "assets": 0,
                "context_deadline_seconds": _context_timeout(),
            },
            status=201,
        )

    run = start_analysis(scan_job, raw_context, max_findings=max_findings)
    return JsonResponse(
        {
            "id": run.pk,
            "scan_job_id": run.scan_job_id,
            "status": run.status,
            "progress": run.progress,
            "created_at": run.created_at,
            "assets": 0,
        },
        status=201,
    )


@csrf_exempt
@require_POST
def analysis_cancel(request, run_id):
    """Cancel an analysis run (POST /api/analysis/<id>/cancel/).

    Cancels awaiting-context / queued / running runs. The running executor
    honours the cancel at its next asset-assessment checkpoint; a cancelled
    run never auto-advances to mitigation.
    """
    try:
        run, db = _load_run(run_id)
    except AnalysisRun.DoesNotExist:
        return JsonResponse({"detail": f"Analysis run {run_id} not found."}, status=400)

    if thread_session_id() and run.session_id != thread_session_id():
        return JsonResponse({"detail": "not found"}, status=404)

    if not cancel_run(run, db):
        return JsonResponse(
            {"detail": f"Analysis run {run_id} is not cancellable (status: {run.status})."},
            status=400,
        )
    return JsonResponse({"id": run.pk, "status": run.status})


@csrf_exempt
@require_POST
def analysis_pause(request, run_id):
    """Pause a queued or running analysis (POST /api/analysis/<id>/pause/).

    The worker stops at its next asset checkpoint and keeps the assessments it
    has already written, so resuming re-uses them rather than redoing the run.
    A paused run is never auto-advanced to mitigation.
    """
    try:
        run, db = _load_run(run_id)
    except AnalysisRun.DoesNotExist:
        return JsonResponse({"detail": f"Analysis run {run_id} not found."}, status=400)

    if thread_session_id() and run.session_id != thread_session_id():
        return JsonResponse({"detail": "not found"}, status=404)

    if not pause_run(run, db):
        return JsonResponse(
            {"detail": f"Analysis run {run_id} is not pausable (status: {run.status})."},
            status=400,
        )
    return JsonResponse({"id": run.pk, "status": run.status, "progress": run.progress})


@csrf_exempt
@require_POST
def analysis_resume(request, run_id):
    """Resume a paused analysis (POST /api/analysis/<id>/resume/).

    Re-queues the run and skips the assets that already have an assessment.
    """
    try:
        run, db = _load_run(run_id)
    except AnalysisRun.DoesNotExist:
        return JsonResponse({"detail": f"Analysis run {run_id} not found."}, status=400)

    if thread_session_id() and run.session_id != thread_session_id():
        return JsonResponse({"detail": "not found"}, status=404)

    if not resume_run(run, db):
        return JsonResponse(
            {"detail": f"Analysis run {run_id} is not resumable (status: {run.status})."},
            status=400,
        )
    return JsonResponse({"id": run.pk, "status": run.status, "progress": run.progress})


@csrf_exempt
def analysis_detail(request, run_id):
    """Return full details for one analysis run (GET /api/analysis/<id>/)."""
    if request.method != "GET":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    try:
        run, db = _load_run(run_id)
    except AnalysisRun.DoesNotExist:
        return JsonResponse({"detail": f"Analysis run {run_id} not found."}, status=400)

    if thread_session_id() and run.session_id != thread_session_id():
        return JsonResponse({"detail": "not found"}, status=404)

    assessments = list(AssetAssessment.objects.using(db).filter(run=run).order_by("id"))

    def _assessment_sort(a):
        m = (a.mosca_result or {}).get("mosca_assessment") or {}
        return (
            _priority_rank(m.get("migration_priority")),
            _priority_rank(m.get("overall_risk")),
            a.pk,
        )

    assessments.sort(key=_assessment_sort)

    summary = run.executive_summary or {}
    summary_rows = sorted(
        summary.get("rows", []),
        key=lambda r: (
            _priority_rank(r.get("migration_priority")),
            _priority_rank(r.get("overall_risk")),
            r.get("asset_id") or 0,
        ),
    )

    data = {
        "id": run.pk,
        "scan_job_id": run.scan_job_id,
        "target": run.scan_job.target,
        "status": run.status,
        "progress": run.progress,
        "error": run.error,
        "created_at": run.created_at,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "repository": run.repository,
        "raw_system_context": run.raw_system_context,
        "risk_context": run.risk_context,
        "executive_summary": run.executive_summary,
        "summary_rows": summary_rows,
        "cbom": run.cbom_document,
        "findings_count": len((run.input_payload or {}).get("findings", [])),
        "truncation": (run.input_payload or {}).get("truncation"),
        "assessments": [_assessment_summary(a) for a in assessments],
    }
    return JsonResponse(data)


@csrf_exempt
def cbom_export(request, run_id=None):
    """Download a Cryptographic Bill of Materials (GET /api/cbom/export/).

    `format` is one of ecdat, cyclonedx-json, cyclonedx-xml. With `run_id` the
    export is narrowed to that analysis run's scan; without it, the whole active
    scope is exported. Always session scoped.
    """
    from segments.ml.cbom.export import (
        CBOMUnavailable,
        UnsupportedCBOMFormat,
        build_export,
    )

    if request.method != "GET":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    output_format = (request.GET.get("format") or "cyclonedx-json").strip().lower()
    db = active_db()
    sid = thread_session_id()

    # An export describes a scan. With none selected there is nothing to
    # describe, and the exporter would otherwise fall back to the thread session
    # and emit a BOM covering every other scan in the database.
    require_scan_scope(sid)

    run = None
    if run_id is not None:
        try:
            run, _db = _load_run(run_id)
        except AnalysisRun.DoesNotExist:
            return JsonResponse({"detail": f"Analysis run {run_id} not found."}, status=404)
        if sid and run.session_id != sid:
            return JsonResponse({"detail": "not found"}, status=404)

    try:
        body, content_type, filename = build_export(
            output_format, db=db, session_id=sid, run=run
        )
    except UnsupportedCBOMFormat as exc:
        # A bad format is the caller's mistake, not a state conflict.
        return JsonResponse({"detail": str(exc)}, status=400)
    except CBOMUnavailable as exc:
        return JsonResponse({"detail": str(exc)}, status=409)

    response = HttpResponse(body, content_type=content_type)
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@csrf_exempt
def analysis_artifacts(request, run_id):
    """Download the full analysis artifact bundle (GET /api/analysis/<id>/artifacts/)."""
    if request.method != "GET":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    try:
        run, db = _load_run(run_id)
    except AnalysisRun.DoesNotExist:
        return JsonResponse({"detail": f"Analysis run {run_id} not found."}, status=400)

    if thread_session_id() and run.session_id != thread_session_id():
        return JsonResponse({"detail": "not found"}, status=404)

    assessments = AssetAssessment.objects.using(db).filter(run=run).order_by("id")
    data = {
        "run": {
            "id": run.pk,
            "scan_job_id": run.scan_job_id,
            "status": run.status,
            "created_at": run.created_at,
            "finished_at": run.finished_at,
        },
        "repository": run.repository,
        "cbom_document": run.cbom_document,
        "risk_context": run.risk_context,
        "executive_summary": run.executive_summary,
        "assessments": [_assessment_summary(a) for a in assessments],
    }
    return JsonResponse(data, content_type="application/json")
