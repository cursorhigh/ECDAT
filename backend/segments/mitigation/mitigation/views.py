"""Function views for the mitigation app (API endpoints)."""

from django.db.models import Count
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from core.modes import active_db, active_mode, db_alias_for_mode
from core.sessions import scope, thread_session_id
from segments.ml.analysis.models import AnalysisRun

from .models import MitigationPlan
from .planner import cancel_plan, trigger_mitigation


def _load_plan(plan_id):
    """Return (plan, db) for a plan.

    One database, so a single lookup. The previous version fell back to the
    other mode's database on a miss, which is meaningless now and cost two extra
    queries before raising a genuine "not found".
    """
    db = active_db()
    plan = (
        MitigationPlan.objects.using(db)
        .select_related("run__scan_job")
        .get(pk=plan_id)
    )
    return plan, db


def _plan_public(plan, include_document=True):
    run = plan.run
    document = plan.document or {}
    summary = document.get("summary") or {}
    by_risk = summary.get("by_risk") or {}
    data = {
        "id": plan.pk,
        "run_id": run.pk,
        "scan_job_id": run.scan_job_id,
        "target": run.scan_job.target,
        "status": plan.status,
        "progress": plan.progress,
        "error": plan.error,
        "created_at": plan.created_at,
        "generated_at": plan.generated_at,
        "summary": {
            "assets": summary.get("assets", 0),
            "urgent": summary.get("urgent", 0),
            "critical_risk": summary.get("critical_risk", by_risk.get("CRITICAL", 0)),
            "high_risk": summary.get("high_risk", by_risk.get("HIGH", 0)),
            "medium_risk": summary.get("medium_risk", by_risk.get("MEDIUM", 0)),
            "low_risk": summary.get("low_risk", by_risk.get("LOW", 0)),
            "quantum_vulnerable": summary.get("quantum_vulnerable", 0),
            "hndl_exposed": summary.get("hndl_exposed", 0),
            "blast_severity": (document.get("blast_radius") or {}).get("severity"),
            "effort_estimate_quarters": summary.get("effort_estimate_quarters"),
        },
    }
    if include_document and plan.status == MitigationPlan.Status.COMPLETE:
        data["document"] = document
    return data


@csrf_exempt
def plan_list(request):
    """List mitigation plans (GET /api/mitigation/)."""
    if request.method != "GET":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    db = active_db()
    plans = (
        scope(MitigationPlan.objects.using(db), thread_session_id())
        .select_related("run__scan_job")
        .annotate(assets_count=Count("document"))
        .order_by("-created_at")[:50]
    )
    return JsonResponse([_plan_public(p, include_document=False) for p in plans], safe=False)


@csrf_exempt
def plan_detail(request, plan_id):
    """Return one plan with its full document (GET /api/mitigation/<id>/)."""
    if request.method != "GET":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    try:
        plan, _db = _load_plan(plan_id)
    except MitigationPlan.DoesNotExist:
        return JsonResponse({"detail": f"Mitigation plan {plan_id} not found."}, status=400)

    if thread_session_id() and plan.session_id != thread_session_id():
        return JsonResponse({"detail": "not found"}, status=404)

    return JsonResponse(_plan_public(plan, include_document=True))


@csrf_exempt
@require_POST
def plan_cancel(request, plan_id):
    """Cancel a mitigation plan (POST /api/mitigation/<id>/cancel/).

    Cancels pending/generating plans; the generating agent thread honours it
    at its next checkpoint (or at completion) and leaves the row cancelled.
    """
    try:
        plan, db = _load_plan(plan_id)
    except MitigationPlan.DoesNotExist:
        return JsonResponse({"detail": f"Mitigation plan {plan_id} not found."}, status=400)

    if thread_session_id() and plan.session_id != thread_session_id():
        return JsonResponse({"detail": "not found"}, status=404)

    if not cancel_plan(plan, db):
        return JsonResponse(
            {"detail": f"Plan {plan_id} is not cancellable (status: {plan.status})."},
            status=400,
        )
    return JsonResponse({"id": plan.pk, "status": plan.status})


@csrf_exempt
@require_GET
def plan_overview(request):
    """Estate-level remediation totals + completed runs lacking a plan.

    Mirrors the old dashboard "Mitigation" page so a frontend can rebuild the
    same view from the API alone.
    """
    db = active_db()
    sid = thread_session_id() or None

    plans = list(
        scope(MitigationPlan.objects.using(db), sid)
        .select_related("run__scan_job")
        .order_by("-created_at")[:50]
    )
    totals = {
        "plans": len(plans),
        "assets": 0,
        "urgent": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "quantum_vulnerable": 0,
        "hndl_exposed": 0,
    }
    for p in plans:
        summary = (p.document or {}).get("summary") or {}
        by_risk = summary.get("by_risk") or {}
        totals["assets"] += summary.get("assets", 0)
        totals["urgent"] += summary.get("urgent", 0)
        totals["high"] += summary.get("high_risk", by_risk.get("HIGH", 0))
        totals["medium"] += summary.get("medium_risk", by_risk.get("MEDIUM", 0))
        totals["low"] += summary.get("low_risk", by_risk.get("LOW", 0))
        totals["quantum_vulnerable"] += summary.get("quantum_vulnerable", 0)
        totals["hndl_exposed"] += summary.get("hndl_exposed", 0)

    runs_unguarded = (
        scope(AnalysisRun.objects.using(db), sid)
        .filter(status=AnalysisRun.Status.COMPLETED, mitigation_plan__isnull=True)
        .annotate(assets_count=Count("assessments"))
        .order_by("-created_at")[:10]
    )
    return JsonResponse(
        {
            "totals": totals,
            "runs_unguarded": [
                {
                    "id": r.pk,
                    "scan_job_id": r.scan_job_id,
                    "target": r.scan_job.target,
                    "assets": r.assets_count,
                    "created_at": r.created_at,
                }
                for r in runs_unguarded
            ],
        }
    )


@csrf_exempt
@require_POST
def plan_generate(request, run_id):
    """Create/regenerate the mitigation plan for a completed analysis run.

    Posts ``{"run": <id>}`` or ``POST /api/mitigation/run/<run_id>/generate/``.
    Returns either 201 (new plan queued) or 200 (existing plan re-dispatched
    or already complete).
    """
    db = active_db()
    try:
        run = AnalysisRun.objects.using(db).get(pk=run_id)
    except AnalysisRun.DoesNotExist:
        return JsonResponse({"detail": f"Analysis run {run_id} not found."}, status=400)

    if run.status != AnalysisRun.Status.COMPLETED:
        return JsonResponse(
            {
                "detail": (
                    f"Analysis run {run_id} is {run.status}; "
                    "only completed runs produce mitigation plans."
                )
            },
            status=400,
        )

    if thread_session_id() and run.session_id != thread_session_id():
        return JsonResponse({"detail": "not found"}, status=404)

    existing = (
        scope(MitigationPlan.objects.using(db), thread_session_id())
        .filter(run=run)
        .first()
    )
    plan = trigger_mitigation(run, db)
    status_code = 201 if existing is None else 200
    return JsonResponse(_plan_public(plan, include_document=False), status=status_code)