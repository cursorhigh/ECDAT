# ECDAT API — Overview

ECDAT is a backend-only API service for **Enterprise Cryptographic Discovery &
Analysis**. It scans local sources (folder walks and external scanner data),
normalizes raw findings into a Cryptographic Bill of Materials (CBOM), runs a
quantum-risk analysis, generates mitigation plans, and produces enterprise
reports — all through a single JSON API under `/api/`.

- Endpoint catalogue: [endpoints.md](endpoints.md)
- Calling flows (scan → analyze → mitigate → report): [calling-flow.md](calling-flow.md)

## Base URL

All routes are mounted under `/api/`:

- `GET /api/health/` — liveness probe (no API key required)
- `core` routes under `/api/session/`
- `discovery` under `/api/` (scans, findings, assets, graph)
- `analysis` under `/api/analysis/`
- `mitigation` under `/api/mitigation/`
- `crypto-scan` pipeline under `/api/crypto/`
- `reports` / `reporting` under `/api/reports/` and `/api/reporting/`

The Django admin (HTML, cookies) lives at `/admin/` and is **not** part of the API.

## Authentication

Every `/api/` route except `/api/health/` requires an API key when
`ECDAT["REQUIRE_API_KEY"]` is enabled. It is **on by default in production**
(`DJANGO_DEBUG=0`) and off in development; override with the environment
variable `ECDAT_REQUIRE_API_KEY=1|0` (see `backend/.env.example`).

Send the key as a header:

```
X-API-Key: ecdat_<prefix>_<secret>
```

or as a standard auth header (both schemes accepted):

```
Authorization: Api-Key ecdat_<prefix>_<secret>
Authorization: Bearer ecdat_<prefix>_<secret>
```

A missing/invalid/revoked key returns a `401 unauthorized` error envelope with a
`WWW-Authenticate: Api-Key realm="ecdat"` challenge header.

### Create / revoke keys

Keys are managed server-side only (never exposed over the network):

```
python manage.py create_api_key "ci pipeline"            # create
python manage.py create_api_key --list                    # list prefixes + names
python manage.py create_api_key --revoke <prefix>         # revoke
python manage.py create_api_key --list --show-masked      # masked form + last use
```

The full key is printed **once**, at creation time (`ecdat_<12-hex-prefix>_<secret>`).
Only a SHA-256 hash of the key is stored. `--scopes ""` (the default) means full
access; scope values are recorded for clients that want to self-document (scope
enforcement is reserved for a later iteration).

## The JSON envelope

Every API response has the same outer shape; clients never parse raw rows.

**Success (any 2xx):**

```json
{
  "success": true,
  "code": "ok",
  "message": "",
  "data": { ... },
  "meta": { "request_id": "…", "timestamp": "2026-…Z" }
}
```

**Error (any 4xx/5xx):**

```json
{
  "success": false,
  "code": "not_found",
  "message": "Scan job 12 not found.",
  "errors": [ { "field": "scan_job", "message": "…" } ],
  "data": null,
  "meta": { "request_id": "…", "timestamp": "…" }
}
```

Guarantees:

1. `data` is always a list or an object (or `null` on errors) — never a bare
   scalar.
2. Non-JSON 2xx payloads pass through untouched: CSV/PDF/HTML exports
   (`/api/reports/*.csv|.pdf|.html`) and the graph endpoint's no-cache headers.
   Anything on those paths that needs JSON is served as JSON (`*.json`, the
   manual endpoints).
3. API 4xx/5xx are always normalized to the JSON error envelope — even if some
   middleware produced an HTML error page.
4. Responses are never double-wrapped: re-sending an already-enveloped response
   is idempotent.

### Machine codes (`code`)

KEEP the code map small — reuse one of these instead of inventing ad-hoc codes
(the map lives in `core/api.py::STATUS_CODES`):

| HTTP | code                |
|------|---------------------|
| 200  | `ok`                |
| 201  | `created`           |
| 202  | `accepted`          |
| 204  | `no_content`        |
| 400  | `bad_request`       |
| 401  | `unauthorized`      |
| 403  | `forbidden`         |
| 404  | `not_found`         |
| 405  | `method_not_allowed`|
| 409  | `conflict`          |
| 422  | `validation_error`  |
| 429  | `too_many_requests` |
| 500  | `internal_error`    |
| 503  | `service_unavailable` |

## Request fingerprints

- **Request id** — echo a caller-supplied `X-Request-Id` header and trace it
  through `meta.request_id` (generated if absent). Log errors with it.
- **Work-session scoping** — nearly every discovery/analysis/reporting endpoint
  is scoped to the active work session. Set it with the `X-ECDAT-Session`
  header (the session id, e.g. `42`) or the `ecdat_session_id` cookie; the
  endpoints that create a scan/session set the cookie automatically. With no
  session, endpoints operate on "All data".

## Bodies

Views accept JSON bodies either raw or enveloped (`{"data": {…}}`); the
unwrapping middleware handles both, so clients can round-trip envelopes.

## Health & degradation

`GET /api/health/` returns the service name, live status, mode, and database:

```json
{
  "success": true,
  "code": "ok",
  "data": {
    "service": "ecdat-backend",
    "status": "ok",
    "active_mode": "actual",
    "active_db": "default"
  },
  "meta": { … }
}
```

- `200` = probe DB reachable.
- `503 service_unavailable` with `data: null` = DB probe failed. The probe
  never 500s.