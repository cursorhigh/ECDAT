"""Endpoint views for work-session management (switch / create / info / reset)."""

import json

from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from segments.ml.analysis.models import AnalysisRun, AssetAssessment
from core.modes import active_db
from segments.scraping.discovery.models import AssetRelation, CryptoAsset, NormalizedFinding, RawFinding, ScanJob

from .models import AuditLog, WorkSession, log_action
from .sessions import ALL, current_id_from_request, set_current, set_thread_session

_DATA_MODELS = (
    ScanJob,
    CryptoAsset,
    RawFinding,
    NormalizedFinding,
    AssetRelation,
    AnalysisRun,
    AssetAssessment,
)


def _scoped(qs, session_id):
    return qs if not session_id else qs.filter(session_id=session_id)


@require_GET
def session_info(request):
    """Return per-layer counts visible under the current scope (JSON).

    Used by the reset-data confirmation modal so it can state exactly what
    will be deleted.
    """
    db = active_db()
    sid = current_id_from_request(request)
    counts = {"scans": 0, "raw_findings": 0, "normalized": 0, "assets": 0,
              "relations": 0, "analysis_runs": 0, "assessments": 0, "audit": 0}
    counts["scans"] = _scoped(ScanJob.objects.using(db), sid).count()
    counts["raw_findings"] = _scoped(RawFinding.objects.using(db), sid).count()
    counts["normalized"] = _scoped(NormalizedFinding.objects.using(db), sid).count()
    counts["assets"] = _scoped(CryptoAsset.objects.using(db), sid).count()
    counts["relations"] = _scoped(AssetRelation.objects.using(db), sid).count()
    counts["analysis_runs"] = _scoped(AnalysisRun.objects.using(db), sid).count()
    counts["assessments"] = _scoped(AssetAssessment.objects.using(db), sid).count()
    counts["audit"] = _scoped(AuditLog.objects.using(db), sid).count()

    current = None
    if sid:
        current = WorkSession.objects.using(db).filter(pk=sid).first()
    return JsonResponse(
        {
            "session_id": sid,
            "session_name": current.name if current else None,
            "scope": "all" if not sid else "session",
            "counts": counts,
        }
    )


@require_GET
def health(request):
    """Service health/liveness probe (GET /api/health/)."""
    from core.modes import active_db, active_mode

    db_up = True
    try:
        from django.db import connections

        connections[active_db()].cursor().execute("SELECT 1")
    except Exception:  # noqa: BLE001 - probe must never 500.
        db_up = False
    return JsonResponse(
        {
            "service": "ecdat-backend",
            "status": "ok" if db_up else "degraded",
            "time": timezone.now().isoformat(),
            "active_mode": active_mode(),
            "active_db": active_db(),
        },
        status=200 if db_up else 503,
    )


@require_GET
def audit(request):
    """Recent audit-log entries (GET /api/session/audit/?limit=200)."""
    try:
        limit = min(1000, max(1, int(request.GET.get("limit", 200))))
    except (TypeError, ValueError):
        limit = 200
    from .models import AuditLog

    sid = current_id_from_request(request) or None
    rows = (
        AuditLog.objects.using(active_db())
        .filter(session_id=sid) if sid else
        AuditLog.objects.using(active_db()).all()
    ).select_related("actor").order_by("-created_at")[:limit]
    return JsonResponse(
        {
            "count": len(list(rows)),
            "entries": [
                {
                    "id": e.pk,
                    "action": e.action,
                    "message": e.message,
                    "target_type": e.target_type,
                    "target_id": e.target_id,
                    "actor": e.actor.username if e.actor else None,
                    "session_id": e.session_id,
                    "created_at": e.created_at,
                }
                for e in rows
            ],
        }
    )


@csrf_exempt
@require_POST
def session_switch(request, session_id):
    """Switch the active work session (returns the new scope)."""
    db = active_db()
    if session_id != ALL and not WorkSession.objects.using(db).filter(pk=session_id).exists():
        return JsonResponse({"detail": f"Session {session_id} does not exist."}, status=400)
    set_current(request, session_id)
    set_thread_session(session_id or None)
    return JsonResponse({"session_id": session_id, "scope": "all" if session_id == ALL else "session"})


@csrf_exempt
@require_POST
def session_create(request):
    """Create a new session (starting empty), activate it, and reload."""
    try:
        data = json.loads(request.body or b"{}")
    except ValueError:
        data = {}
    name = (data.get("name") or "").strip()[:128]
    if not name:
        return JsonResponse({"detail": "Missing session name."}, status=400)

    db = active_db()
    ws, created = WorkSession.objects.using(db).get_or_create(name=name)
    set_current(request, ws.pk)
    log_action("system", f"Created work session {ws.name!r}", "worksession", ws.pk)
    return JsonResponse({"id": ws.pk, "name": ws.name, "created": created})


@csrf_exempt
@require_POST
def session_reset(request):
    """Reset data for the current scope (session or everything) and reload."""
    db = active_db()
    sid = current_id_from_request(request)
    scope_kwargs = {"session_id": sid} if sid else {}

    def count_delete(cls, label):
        rows, _detail = _scoped(cls.objects.using(db), sid).delete()
        return rows

    deleted = {
        "analysis_runs": count_delete(AnalysisRun, "analysis_runs"),
        "assessments": count_delete(AssetAssessment, "assessments"),
        "scan_jobs": count_delete(ScanJob, "scan_jobs"),
        "assets": count_delete(CryptoAsset, "assets"),
        "audit": count_delete(AuditLog, "audit"),
    }
    # RawFinding / NormalizedFinding / AssetRelation are removed by cascade
    # from ScanJob / CryptoAsset above; delete any stragglers defensively.
    deleted["raw_findings"] = count_delete(RawFinding, "raw_findings")
    deleted["normalized"] = count_delete(NormalizedFinding, "normalized")
    deleted["relations"] = count_delete(AssetRelation, "relations")

    label = f"session {sid}" if sid else "all sessions"
    if sid:
        # Remove the workspace itself and leave "All data" active afterwards.
        deleted["workspace"] = WorkSession.objects.using(db).filter(pk=sid).delete()[0]
        set_current(request, None)
        set_thread_session(None)
        log_action("system", f"Reset findings data for {label} (workspace removed)",
                   "worksession", str(sid), session_id=0)
    else:
        log_action("system", f"Reset findings data for {label}", "worksession", str(sid) or "")
    return JsonResponse({"ok": True, "session_id": sid, "deleted": deleted})