"""Function views for the mitigation app (API endpoints)."""

from django.db.models import Count
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from core.modes import active_db, db_alias_for_mode
from core.sessions import scope, thread_session_id
from analysis.models import AnalysisRun

from .models import MitigationPlan
from .planner import trigger_mitigation


def _load_plan(plan_id):
    """Return (plan, db) for a plan, resolved from the run's own mode database."""
    db = active_db()
    try:
        plan = MitigationPlan.objects.using(db).get(pk=plan_id)
    except MitigationPlan.DoesNotExist:
        fallback = "demo" if db != "demo" else "default"
        plan = MitigationPlan.objects.using(fallback).get(pk=plan_id)
    db = db_alias_for_mode(plan.mode)
    return (
        MitigationPlan.objects.using(db)
        .select_related("run__scan_job")
        .get(pk=plan_id),
        db,
    )


def _plan_public(plan, include_document=True):
    run = plan.run
    document = plan.document or {}
    summary = document.get("summary") or {}
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