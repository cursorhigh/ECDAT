"""Template context processors."""

from core.modes import active_db
from .sessions import ALL, current_id_from_request
from .models import WorkSession


def work_session(request):
    """Inject the session switcher data into every template.

    Provides: ``work_sessions`` (all sessions), ``current_ws`` (active
    WorkSession instance or None) and ``current_session_id`` (pk, 0 = All).
    """
    db = active_db()
    sessions = list(WorkSession.objects.using(db).order_by("name"))
    sid = current_id_from_request(request)
    current = next((s for s in sessions if s.pk == sid), None)
    return {
        "work_sessions": sessions,
        "current_ws": current,
        "current_session_id": sid or ALL,
    }