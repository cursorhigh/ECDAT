"""ECDAT API envelope: one JSON contract for every request/response.

Every HTTP response from the API carries the same outer shape; clients never
parse raw rows out of thin responses. Two envelopes:

Success (HTTP 2xx)::

    {
      "success": true,
      "code": "ok",                    # machine code, see STATUS_CODES
      "message": "",
      "data": { ... },                 # the payload (object or list)
      "meta": { "request_id", "timestamp" }
    }

Error (HTTP 4xx/5xx)::

    {
      "success": false,
      "code": "not_found",
      "message": "Scan job 12 not found.",
      "errors": [],                    # [{field, message}] for validation
      "data": null,
      "meta": { "request_id", "timestamp" }
    }

Requests may mirror the shape: a JSON body wrapped as ``{"data": {...}}`` is
automatically unwrapped before it reaches a view, so both raw and enveloped
request bodies are accepted everywhere (see EnvelopeMiddleware).
"""

import hashlib
import hmac
import json
import secrets
import uuid

from django.conf import settings
from django.core.exceptions import (
    ObjectDoesNotExist,
    PermissionDenied,
    SuspiciousOperation,
    ValidationError as DjangoValidationError,
)
from django.http import Http404, HttpResponse, JsonResponse
from django.utils import timezone

from rest_framework import exceptions as drf_exceptions

# HTTP status -> stable machine-readable code. Kept deliberately small: reuse
# one of these instead of inventing ad-hoc codes.
STATUS_CODES = {
    200: "ok",
    201: "created",
    202: "accepted",
    204: "no_content",
    301: "moved_permanently",
    302: "found",
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    410: "gone",
    422: "validation_error",
    429: "too_many_requests",
    500: "internal_error",
    501: "not_implemented",
    502: "bad_gateway",
    503: "service_unavailable",
}

REQUEST_ID_HEADER = "X-Request-Id"
SESSION_HEADER = "X-ECDAT-Session"
API_KEY_HEADER = "X-API-Key"
API_PREFIXES = ("/api/",)
# Endpoints reachable without an API key (liveness probes, etc.).
API_KEY_EXEMPT_PATHS = ("/api/health/",)
API_KEY_PREFIX = "ecdat"
SECRET_BYTES = 24


class ApiError(Exception):
    """Raise inside a view to produce an enveloped error response."""

    def __init__(self, status=400, code=None, message="", errors=None):
        self.status = status
        self.code = code or STATUS_CODES.get(status, "bad_request")
        self.message = message
        self.errors = errors or []
        super().__init__(self.message)


NO_SCAN_SELECTED = "no_scan_selected"

NO_SCAN_SELECTED_MESSAGE = (
    "No scan is selected. Every scan owns its own session, so there is no data "
    "scope to answer from. Open a scan from the audit history, or start one."
)


def require_scan_scope(session_id):
    """Refuse an action that belongs to a scan when no scan is selected.

    List endpoints deliberately keep returning an empty result, because "no
    findings" is a real answer for a list. This is for the endpoints where the
    absence is an error rather than an answer: exporting a BOM, rebuilding the
    graph, correlating, or asking about one specific node or run. Those used to
    quietly operate on whatever the thread session happened to hold, which is
    how a rebuild could touch every scan in the database.
    """
    if session_id:
        return session_id
    raise ApiError(409, NO_SCAN_SELECTED, NO_SCAN_SELECTED_MESSAGE)


def request_id(request):
    """Request id for a request: caller-provided or generated."""
    rid = getattr(request, "_ecdat_request_id", None)
    if rid:
        return rid
    rid = request.headers.get(REQUEST_ID_HEADER) or uuid.uuid4().hex[:16]
    setattr(request, "_ecdat_request_id", rid)
    return rid


def _meta(request):
    return {
        "request_id": request_id(request),
        "timestamp": timezone.now().isoformat(),
    }


def build_envelope(request, payload, status, success, code=None, message="", errors=None):
    """Serialize ``payload`` (or error fields) into the standard envelope."""
    if success:
        return {
            "success": True,
            "code": code or STATUS_CODES.get(status, "ok"),
            "message": message,
            "data": payload,
            "meta": _meta(request),
        }
    return {
        "success": False,
        "code": code or STATUS_CODES.get(status, "internal_error"),
        "message": message,
        "errors": errors or [],
        "data": None,
        "meta": _meta(request),
    }


def wrap_response(request, response):
    """Wrap a JSON HttpResponse in the envelope (idempotent).

    Leaves non-JSON 2xx responses (CSV, PDF, HTML reports) untouched. API
    4xx/5xx are always normalized to the JSON error envelope even when a
    plain view produced an HTML/plain error page (e.g. Django debug pages or
    `require_POST` 405s), so API clients only ever see JSON.

    A JSON body that is a *file download* is also left alone: an attachment
    is consumed by whatever opens the file, not by an API client, and wrapping
    it would silently produce a document the recipient cannot parse (a CBOM
    exported as `{"success": true, "data": {...}}` is not a valid CBOM).

    Headers from the original response (Set-Cookie, X-Frame-Options, ...) are
    copied onto the wrapped response.
    """
    if not response.status_code or response.status_code == 204:
        return response
    if "attachment" in (response.get("Content-Disposition") or "").lower():
        return response
    content_type = response.get("Content-Type", "")
    if content_type.startswith("application/json"):
        try:
            body = json.loads(response.content.decode("utf-8") or "null")
        except (ValueError, UnicodeDecodeError):
            return response
        # Never double-wrap.
        if isinstance(body, dict) and "success" in body and "meta" in body:
            return response

        status = response.status_code
        if status < 400:
            payload = build_envelope(
                request, body, status, success=True,
                code=STATUS_CODES.get(status, "ok"),
                message="",
            )
        else:
            message, errors = _extract_error(body)
            payload = build_envelope(
                request, None, status, success=False,
                code=STATUS_CODES.get(status, "bad_request"),
                message=message,
                errors=errors,
            )
        return _wrap_with_headers(request, response, payload, status)

    if response.status_code >= 400:
        return _wrap_with_headers(
            request, response,
            build_envelope(request, None, response.status_code, success=False,
                           code=STATUS_CODES.get(response.status_code, "bad_request"),
                           message=response.reason_phrase or "Request failed"),
            response.status_code,
        )
    return response


def _wrap_with_headers(request, original, payload, status):
    wrapped = JsonResponse(payload, status=status)
    for key, value in original.items():
        if key.lower() in ("content-length", "content-type"):
            continue
        wrapped[key] = value
    # Session / csrf cookies live in the response's SimpleCookie, outside the
    # plain header dict — copy them so set_cookie() results (e.g. the work
    # session cookie set by SessionMiddleware) are not dropped.
    if getattr(original, "cookies", None):
        for key, cookie in original.cookies.items():
            wrapped.cookies[key] = cookie
    wrapped[REQUEST_ID_HEADER] = request_id(request)
    return wrapped


def _extract_error(body):
    """Normalize a JSON error body into (message, errors)."""
    if not isinstance(body, dict):
        return str(body) or "Request failed", []
    detail = body.get("detail") or body.get("message") or (body.get("error") if isinstance(body.get("error"), str) else "")
    raw_errors = body.get("errors", [])
    errors = []
    if isinstance(raw_errors, dict):
        for field, msgs in raw_errors.items():
            if isinstance(msgs, (list, tuple)):
                for m in msgs:
                    errors.append({"field": field, "message": str(m)})
            else:
                errors.append({"field": field, "message": str(msgs)})
    elif isinstance(raw_errors, (list, tuple)):
        for e in raw_errors:
            if isinstance(e, dict):
                errors.append({"field": str(e.get("field", "")), "message": str(e.get("message", e))})
            else:
                errors.append({"field": "", "message": str(e)})
    return str(detail) if detail else "Request failed", errors


class EnvelopeMiddleware:
    """Wrap every /api/ response in the JSON envelope.

    Also:
    - accepts an enveloped request body ``{"data": {...}}`` by unwrapping it,
    - assigns/echoes an X-Request-Id (header + envelope meta),
    - maps common exceptions (Http404, PermissionDenied, validation, DRF
      errors) onto the error envelope,
    - declares API requests CSRF-exempt (the API authenticates via API key /
      header, not browser cookies; /admin keeps CSRF).
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path_info
        is_api = path.startswith(API_PREFIXES)

        if is_api and not path.startswith("/admin"):
            request.csrf_processing_done = True

        if is_api and request.method in ("POST", "PUT", "PATCH", "DELETE"):
            _unwrap_request_body(request)

        try:
            response = self.get_response(request)
        except Exception as exc:  # noqa: BLE001 - normalize to an envelope
            if not is_api:
                raise
            response = self._exception_response(request, exc)

        if is_api:
            response = wrap_response(request, response)
        return response

    def process_exception(self, request, exception):
        """Render a view's exception as the error envelope.

        The `except` block in `__call__` only ever sees failures raised by the
        middleware around the view. An exception raised *inside* a view is caught
        by Django's `convert_exception_to_response` first, so it reaches this
        class already turned into a bare 500 response -- with the exception type,
        the error code and the message all lost. That made the `ApiError` branch
        below unreachable dead code: a view could raise a precise 409 and the
        client still received a message-less 500.

        `process_exception` is the hook Django calls for view exceptions before
        that conversion, so this is the only place the envelope can be built with
        the real status, code and message intact.
        """
        if not request.path_info.startswith(API_PREFIXES):
            return None
        if settings.DEBUG_PROPAGATE_EXCEPTIONS:
            return None
        return self._exception_response(request, exception)

    def _exception_response(self, request, exc):
        if isinstance(exc, ApiError):
            return JsonResponse(
                build_envelope(request, None, exc.status, success=False, code=exc.code,
                               message=exc.message, errors=exc.errors),
                status=exc.status,
            )
        if isinstance(exc, (Http404,)):
            return JsonResponse(
                build_envelope(request, None, 404, success=False, code="not_found",
                               message=str(exc) or "Not found"),
                status=404,
            )
        if isinstance(exc, PermissionDenied):
            return JsonResponse(
                build_envelope(request, None, 403, success=False, code="forbidden",
                               message="Permission denied"),
                status=403,
            )
        if isinstance(exc, (SuspiciousOperation,)):
            return JsonResponse(
                build_envelope(request, None, 400, success=False, code="bad_request",
                               message=str(exc) or "Suspicious request"),
                status=400,
            )
        if isinstance(exc, (ObjectDoesNotExist,)):
            return JsonResponse(
                build_envelope(request, None, 404, success=False, code="not_found",
                               message=str(exc)),
                status=404,
            )
        if isinstance(exc, DjangoValidationError):
            errors = [{"field": "", "message": (", ".join(exc.messages) if hasattr(exc, "messages") else str(exc))}]
            return JsonResponse(
                build_envelope(request, None, 422, success=False, code="validation_error",
                               message="Validation failed", errors=errors),
                status=422,
            )
        if isinstance(exc, drf_exceptions.APIException):
            return JsonResponse(
                build_envelope(request, None, exc.status_code, success=False,
                               code=STATUS_CODES.get(exc.status_code, "bad_request"),
                               message=str(getattr(exc, "detail", exc)),
                               errors=_detail_errors(getattr(exc, "detail", None))),
                status=exc.status_code,
            )
        # Break the envelope promise in debug with the traceback, otherwise
        # return a generic 500 (the detail is logged by Django).
        response = HttpResponse(
            json.dumps(build_envelope(request, None, 500, success=False, code="internal_error",
                                      message="Internal server error")),
            content_type="application/json",
            status=500,
        )
        import logging

        logging.getLogger("core.api").exception("Unhandled exception", exc_info=exc)
        return response


def _detail_errors(detail):
    """Convert a DRF error detail (dict/list/str) into {field,message}."""
    if isinstance(detail, dict):
        return [
            {"field": str(field), "message": msg if isinstance(msg, str) else str(msg)}
            for field, msg in detail.items()
        ]
    if isinstance(detail, (list, tuple)):
        return [{"field": "", "message": str(m)} for m in detail]
    return [{"field": "", "message": str(detail)}]


def _unwrap_request_body(request):
    """Accept ``{"data": {...}}`` request bodies by unwrapping ``data``.

    Only touches requests whose body is a single-key JSON object whose value
    is an object or list. Raw bodies are passed through untouched, so views
    keep their existing `json.loads(request.body)` parsing either way.
    """
    if request.body:
        try:
            parsed = json.loads(request.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return
        if (
            isinstance(parsed, dict)
            and set(parsed.keys()) == {"data"}
            and isinstance(parsed.get("data"), (dict, list))
        ):
            new_body = json.dumps(parsed["data"]).encode("utf-8")
            request._body = new_body
            # Django caches request.body on first read; reset both the cached
            # property value and the raw field so the view sees the unwrapped
            # body.
            request.__dict__["body"] = new_body


# ---------------------------------------------------------------------------
# API-key authentication
# ---------------------------------------------------------------------------

def hash_secret(secret):
    """Return the hex SHA-256 of a key secret."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def generate_key():
    """Create a fresh credential.

    Returns ``(full_key, prefix, hashed)`` where ``full_key`` has the shape
    ``ecdat_<prefix>_<secret>`` and is the only time the secret is available.
    """
    prefix = secrets.token_hex(6)
    secret = secrets.token_urlsafe(SECRET_BYTES)
    return f"{API_KEY_PREFIX}_{prefix}_{secret}", prefix, hash_secret(secret)


def parse_key(value):
    """Split a presented key into ``(prefix, secret)`` or ``None``."""
    if not value:
        return None
    parts = value.strip().split("_", 2)
    if len(parts) != 3 or parts[0] != API_KEY_PREFIX:
        return None
    return parts[1], parts[2]


def create_api_key(name, scopes="", db=None):
    """Create + persist an ApiKey; returns ``(instance, full_key)``."""
    from .modes import active_db
    from .models import ApiKey

    db = db or active_db()
    full_key, prefix, hashed = generate_key()
    instance = ApiKey.objects.using(db).create(
        name=name, prefix=prefix, hashed_key=hashed, scopes=scopes or ""
    )
    return instance, full_key


def extract_key(request):
    """Read the presented key from X-API-Key or Authorization."""
    value = request.headers.get(API_KEY_HEADER)
    if value:
        return value.strip()
    auth = request.headers.get("Authorization", "")
    for scheme in ("Api-Key ", "Bearer ", "api-key "):
        if auth.startswith(scheme):
            return auth[len(scheme):].strip()
    return ""


def resolve_api_key(value, db=None):
    """Return the matching active ApiKey, or None."""
    from .modes import active_db
    from .models import ApiKey

    parsed = parse_key(value)
    if not parsed:
        return None
    prefix, secret = parsed
    db = db or active_db()
    key = ApiKey.objects.using(db).filter(prefix=prefix, is_active=True).first()
    if key is None:
        return None
    if not hmac.compare_digest(key.hashed_key, hash_secret(secret)):
        return None
    return key


def api_key_required():
    """Whether API-key auth is enforced for this deployment."""
    from django.conf import settings

    return bool(settings.ECDAT.get("REQUIRE_API_KEY", False))


class ApiKeyMiddleware:
    """Enforce API-key auth on /api/ routes when enabled.

    Disabled by default in DEBUG; enabled by default when ``DEBUG`` is off.
    Override with the ``ECDAT_REQUIRE_API_KEY`` environment variable. Requests
    to exempt paths (health) and non-API paths (/admin) pass through.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path_info
        if (
            path.startswith(API_PREFIXES)
            and not path.startswith("/admin")
            and path not in API_KEY_EXEMPT_PATHS
            and api_key_required()
        ):
            key = resolve_api_key(extract_key(request), db=_active_db())
            if key is None:
                response = JsonResponse(
                    build_envelope(
                        request, None, 401, success=False, code="unauthorized",
                        message="Missing or invalid API key.",
                    ),
                    status=401,
                )
                response["WWW-Authenticate"] = 'Api-Key realm="ecdat"'
                return response
            from django.utils import timezone

            request.api_key = key
            type(key).objects.using(_active_db()).filter(pk=key.pk).update(
                last_used_at=timezone.now()
            )
        return self.get_response(request)


def _active_db():
    from .modes import active_db

    return active_db()