"""Request middleware for work-session scoping."""

from .sessions import clear_thread_session, current_id_from_request, set_thread_session


class WorkSessionMiddleware:
    """Mirror the request's active work session into a thread-local.

    Runs after SessionMiddleware so ``request.session`` exists. Views and
    ``log_action`` read the mirror via ``core.sessions.thread_session_id()``.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        set_thread_session(current_id_from_request(request))
        try:
            return self.get_response(request)
        finally:
            clear_thread_session()