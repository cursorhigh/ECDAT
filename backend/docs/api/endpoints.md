# ECDAT API — Endpoint Catalogue

Every response is envelope-wrapped (see [README.md](README.md)). `req` /
`body` columns describe the JSON request body where one is read; most GETs are
scoped to the active work session (`X-ECDAT-Session` header or cookie).

## Service

| Method | Path              | Auth  | Purpose                            |
|--------|-------------------|-------|------------------------------------|
| GET    | `/api/health/`    | none  | Liveness probe (mode + db)         |

## Sessions — `/api/session/`

| Method | Path                | Body            | Response (`data`)                            |
|--------|---------------------|-----------------|----------------------------------------------|
| GET    | `/api/session/info/` | —               | session id/name, scope, per-layer `counts`   |
| POST   | `/api/session/create/` | `{ "name": "…" }` | `{ id, name, created }`; sets session cookie |
| POST   | `/api/session/switch/<id>/` | —      | `{ session_id, scope: "session"\|"all" }`    |
| POST   | `/api/session/reset/` | —              | resets current scope data; reload-friendly   |
| GET    | `/api/session/audit/?limit=200` | —    | recent audit entries (`count` + `entries[]`) |

`session/switch/0` switches to "All data" scope. `reset` clears the data for
the current scope (everything when no session). `session_create` notes that a
missing `name` returns `400 bad_request`.

## Discovery — `/api/` (Root router)

DRF read-only list/detail viewsets; `/api/<resource>/` and
`/api/<resource>/<pk>/`. Lists are ordered and support standard DRF query
params (`?search=…` where declared, `?ordering=…`).

| Resource              | Search            | Ordering                 | Notes                    |
|-----------------------|-------------------|--------------------------|--------------------------|
| `/api/scans/`         | —                 | created_at, status, source_type | newest first     |
| `/api/raw-findings/`  | location          | ingested_at              |                          |
| `/api/normalized-findings/` | algorithm, library, protocol | algorithm, key_size |          |
| `/api/assets/`        | name, algorithm, location, owner | name, family, key_size |       |
| `/api/relations/`     | —                 | —                        | links between assets     |
| `/api/stats/`         | —                 | —                        | aggregate counts + groupings |

### Action endpoints

| Method | Path                     | Body / query        | Response (`data`) / meaning                     |
|--------|--------------------------|---------------------|-------------------------------------------------|
| GET    | `/api/browse/?path=`     | —                   | `{ path, parent, folders[] }` for the path picker |
| GET    | `/api/scan-preview/?scan_type=quick\|whole\|specified` | — | platform + `roots[]` a scan will walk |
| POST   | `/api/start-scan/`       | `{ scan_type, source_type, target, options }` | `201 created`, scan row + `session` |
| POST   | `/api/run-demo-scan/`    | —                   | `201 created`, demo ScanJob row                 |
| POST   | `/api/scans/<id>/cancel/` | —                  | `{ id, status }`                                 |
| POST   | `/api/scan-data/`        | `{ source_type, target, findings: [] }` | `201 created`; ingest external scanner data |
| GET    | `/api/graph/`            | —                   | everything the asset graph renders (assets, findings, relations) |
| POST   | `/api/graph/correlate/`  | —                   | `{ created, total }`; rebuild correlation edges |

`start-scan` body: `scan_type` one of `quick|whole|specified`, `source_type`
defaults to `source_code`, `target` a local folder path (specified only),
`options` an object of booleans. Invalid targets are rejected with
`400 bad_request` and no session is left behind.

## Analysis — `/api/analysis/`

| Method | Path                     | Body / query            | Response (`data`) / meaning                     |
|--------|--------------------------|--------------------------|-------------------------------------------------|
| GET    | `/api/analysis/`         | —                        | recent runs (last 50), summary fields           |
| GET    | `/api/analysis/awaiting/`| —                        | runs paused on context choice (+ `seconds_left`) |
| POST   | `/api/analysis/start/`   | `{ scan_job, max_findings, raw_system_context }` | `201 created` new run; `200` reused awaiting/active run; `409 conflict` if already queued |
| GET    | `/api/analysis/<id>/`    | —                        | full run detail: assessments, summaries, CBOM   |
| POST   | `/api/analysis/<id>/cancel/` | —                   | `{ id, status }`                                 |
| GET    | `/api/analysis/<id>/artifacts/` | —               | artifact bundle (run meta, cbom, risk context, executive summary, assessments) |

Only **completed** scans can be analyzed (`400 bad_request` otherwise).
`raw_system_context` is optional; when an awaiting run exists it is committed to
that run instead of starting a duplicate.

## Mitigation — `/api/mitigation/`

| Method | Path                              | Body           | Response (`data`) / meaning               |
|--------|-----------------------------------|----------------|-------------------------------------------|
| GET    | `/api/mitigation/`                | —              | list plans (last 50, without full doc)    |
| GET    | `/api/mitigation/overview/`       | —              | remediation totals + completed runs lacking a plan |
| GET    | `/api/mitigation/<id>/`           | —              | one plan with its full `document`        |
| POST   | `/api/mitigation/<id>/cancel/`    | —              | `{ id, status }`                          |
| POST   | `/api/mitigation/run/<run_id>/generate/` | `{ run }` (or empty) | `201 created` new plan / `200` re-dispatched |

Only **completed** analysis runs produce mitigation plans
(`400 bad_request` otherwise). Plan `document` is only included on detail /
generate responses when the plan is `COMPLETE`.

## Crypto-scan pipeline — `/api/crypto/`

| Method | Path                         | Body            | Response (`data`) / meaning                  |
|--------|------------------------------|-----------------|----------------------------------------------|
| POST   | `/api/crypto/scan/start/`    | `{ path }`      | `201 created`; walk path, chunk across CPUs, enqueue chunks: `{ scan_id, path, total_chunks, total_files, status, session }` |
| GET    | `/api/crypto/scan/<id>/status/` | —           | `{ scan_id, done, total, status }`           |
| POST   | `/api/crypto/scan/<id>/cancel/` | —           | `{ scan_id, status }`                        |

Chunk tasks run through huey (see heartbeat / sweep helpers); poll `status/`
for progress. Requires a local absolute directory as `path`.

## Reporting — `/api/reporting/`

| Method | Path                 | Response (`data`) / meaning                          |
|--------|----------------------|------------------------------------------------------|
| GET    | `/api/reporting/overview/` | estate KPIs, risk split, PQC workflow, recent scans |
| GET    | `/api/reporting/pipeline/` | `{ stages: [...] }` pipeline counts           |
| GET    | `/api/reporting/audit/?limit=200` | recent audit entries (mirrors `/api/session/audit/`) |

## Reports & exports — `/api/reports/`

These are **file** endpoints (not JSON envelopes), scoped to the active work
session:
`GET /api/reports/assets.csv`, `assets.json`, `raw.csv`, `normalized.csv`,
`full.html` (inline preview), `full.pdf` (attachment), plus
`POST /api/reports/full.json` which returns `{ b64, filename, mime, format,
size, generated_at, scope }` for browser-side download.

## Error examples

All errors use the shared envelope; `message` holds human text, `errors[]`
holds field-level `{field, message}` details when present. Invalid JSON,
missing required fields, wrong scan/run status, and cross-session access all
map to `400 bad_request` or `404 not_found`.