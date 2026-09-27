"""Work-session scoping helpers.

A WorkSession partitions discovery / inventory / graph / analysis / audit data
into independent workspaces (e.g. one session per scan result / analysis run).

Current-session resolution has two layers that always agree:

- request layer: ``request.session[SESSION_KEY]`` — written by the
  ``core.views`` switch/create endpoints and read by the context processor.
- background layer: a thread-local mirror set by ``WorkSessionMiddleware`` per
  request (so huey tasks and ``log_action`` still know the workspace). When no
  request is running the mirror is empty.

Scoping rule: a session pk filters every data layer to that session's rows.
No session (or pk ``0`` = the dashboard's "All data" switcher option) shows
everything — including the legacy ``session=NULL``/global rows.
"""

import threading

from .models import WorkSession

SESSION_KEY = "ecdat_session_id"
SESSION_HEADER = "HTTP_X_ECDAT_SESSION"
ALL = 0  # switcher value representing "All data" (no scoping)

_local = threading.local()


def current_id_from_request(request):
    """Return the active session pk for a request (0 = All data).

    An explicit ``X-ECDAT-Session`` header (API clients) takes precedence over
    the cookie session (admin/browser sessions). The value is an integer pk,
    or ``0`` for "All data".
    """
    header = request.META.get(SESSION_HEADER)
    if header:
        try:
            return int(header)
        except (TypeError, ValueError):
            return ALL
    return request.session.get(SESSION_KEY, ALL)


def set_current(request, session_id):
    """Persist the active session pk (or clear it) on the request session."""
    if session_id:
        request.session[SESSION_KEY] = int(session_id)
    else:
        request.session.pop(SESSION_KEY, None)


def set_thread_session(session_id):
    _local.session_id = session_id if session_id else None


def clear_thread_session():
    _local.session_id = None


def thread_session_id():
    """Session pk captured by WorkSessionMiddleware for this thread, or None."""
    return getattr(_local, "session_id", None)


def scope(queryset, session_id=None):
    """Narrow a queryset to one session, or return nothing at all.

    With no active session this used to return the queryset unfiltered, which
    meant "no session selected" quietly became "every session's data". Two scans
    then rendered as one list, and a report could be built from another scan's
    findings without anything looking wrong.

    Each scan owns its own session, so an absent session means there is nothing
    to show rather than everything to show. The one place that legitimately
    spans sessions is the audit scan history, and it asks for the rows
    explicitly instead of relying on this default.
    """
    if session_id:
        return queryset.filter(session_id=session_id)
    return queryset.none()


def default_session():
    """Newest WorkSession in the active database, or None."""
    return WorkSession.objects.order_by("-created_at").first()


def create_scan_session(request, label, using=None):
    """Create a brand-new WorkSession for this scan and activate it.

    Returns the created WorkSession. The name is the (truncated) ``label``
    followed by a timestamp; if that name is already taken a ``· N`` suffix is
    appended until a unique name is found. The new session is set both on the
    request (``set_current``) and on the thread mirror
    (``set_thread_session``) so scoped reads / ``log_action`` within this same
    request see the new workspace immediately.
    """
    from django.utils import timezone

    from .modes import active_db

    db = using or active_db()
    label = (label or "").strip() or "scan"
    base = label[:80]
    when = timezone.localtime().strftime("%Y-%m-%d %H:%M")

    name = f"{base} · {when}"
    suffix = 1
    while WorkSession.objects.using(db).filter(name=name).exists():
        suffix += 1
        name = f"{base} · {when} · {suffix}"
    ws = WorkSession.objects.using(db).create(name=name)
    set_current(request, ws.pk)
    set_thread_session(ws.pk)
    return ws