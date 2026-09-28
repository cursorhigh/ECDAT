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
    """Rows for one session, or none.

    This returned the whole table when no session was selected, so the scope
    banner reported the estate's row counts as if they belonged to the scan on
    screen. It now defers to `scope`, which treats an absent session as empty.
    """
    from .sessions import scope

    return scope(qs, session_id)


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
            "scope": "none" if not sid else "session",
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


@require_GET
def scan_history(request):
    """Every scan, across every session (GET /api/scan-history/).

    This is the one view that intentionally spans sessions, and it exists because
    removing the "all data" scope left no way to find a previous scan. Each scan
    owns its own session, so a session *is* a scan, and listing sessions with
    their jobs is the history.

    It reports only what was recorded. It deliberately does not join findings or
    assets into the totals, so it cannot become a second source of scan data that
    disagrees with the session it describes.
    """
    from .models import WorkSession

    db = active_db()
    try:
        limit = min(500, max(1, int(request.GET.get("limit", 100))))
    except (TypeError, ValueError):
        limit = 100

    sessions = list(WorkSession.objects.using(db).order_by("-created_at")[:limit])

    job_rows = []
    if sessions:
        from segments.scraping.discovery.models import ScanJob

        job_rows = list(
            ScanJob.objects.using(db)
            .filter(session_id__in=[s.pk for s in sessions])
            .values(
                "id", "session_id", "source_type", "target", "status",
                "findings_count", "items_scanned", "items_skipped", "created_at",
            )
            .order_by("created_at")
        )

    jobs_by_session: dict = {}
    for job in job_rows:
        jobs_by_session.setdefault(job["session_id"], []).append(job)

    active_id = current_id_from_request(request) or None

    return JsonResponse(
        {
            "count": len(sessions),
            "active_session_id": active_id,
            "sessions": [
                {
                    "id": session.pk,
                    "name": session.name,
                    "created_at": session.created_at,
                    "is_active": session.pk == active_id,
                    "scans": jobs_by_session.get(session.pk, []),
                }
                for session in sessions
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


@csrf_exempt
def delete_scan_history_session(request, session_id):
    """Delete a specific session/scan run and all its cascaded findings & reports."""
    if request.method not in ("DELETE", "POST"):
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    db = active_db()
    session = WorkSession.objects.using(db).filter(pk=session_id).first()
    if not session:
        return JsonResponse({"detail": f"Session {session_id} not found."}, status=404)

    name = session.name
    # Delete all associated data
    try:
        from segments.mitigation.mitigation.models import MitigationPlan
        MitigationPlan.objects.using(db).filter(session_id=session_id).delete()
    except Exception:
        pass

    AnalysisRun.objects.using(db).filter(session_id=session_id).delete()
    AssetAssessment.objects.using(db).filter(session_id=session_id).delete()
    ScanJob.objects.using(db).filter(session_id=session_id).delete()
    CryptoAsset.objects.using(db).filter(session_id=session_id).delete()
    RawFinding.objects.using(db).filter(session_id=session_id).delete()
    NormalizedFinding.objects.using(db).filter(session_id=session_id).delete()
    AssetRelation.objects.using(db).filter(session_id=session_id).delete()
    AuditLog.objects.using(db).filter(session_id=session_id).delete()
    session.delete()

    active_id = current_id_from_request(request)
    if active_id == session_id:
        remaining = WorkSession.objects.using(db).order_by("-created_at").first()
        new_sid = remaining.pk if remaining else None
        set_current(request, new_sid)
        set_thread_session(new_sid)

    return JsonResponse({"ok": True, "deleted_session_id": session_id, "name": name})


@csrf_exempt
def clear_all_scan_history(request):
    """Clear all scan history and sessions across the workspace."""
    if request.method not in ("DELETE", "POST"):
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    db = active_db()
    try:
        from segments.mitigation.mitigation.models import MitigationPlan
        MitigationPlan.objects.using(db).all().delete()
    except Exception:
        pass

    AnalysisRun.objects.using(db).all().delete()
    AssetAssessment.objects.using(db).all().delete()
    ScanJob.objects.using(db).all().delete()
    CryptoAsset.objects.using(db).all().delete()
    RawFinding.objects.using(db).all().delete()
    NormalizedFinding.objects.using(db).all().delete()
    AssetRelation.objects.using(db).all().delete()
    AuditLog.objects.using(db).all().delete()
    WorkSession.objects.using(db).all().delete()

    set_current(request, None)
    set_thread_session(None)

    return JsonResponse({"ok": True, "cleared_all": True})


@csrf_exempt
def delete_scan_job(request, scan_id):
    """Delete a single scan job and its findings."""
    if request.method not in ("DELETE", "POST"):
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    db = active_db()
    job = ScanJob.objects.using(db).filter(pk=scan_id).first()
    if not job:
        return JsonResponse({"detail": f"Scan job {scan_id} not found."}, status=404)

    AnalysisRun.objects.using(db).filter(scan_job=job).delete()
    RawFinding.objects.using(db).filter(scan_job=job).delete()
    job.delete()

    return JsonResponse({"ok": True, "deleted_scan_id": scan_id})