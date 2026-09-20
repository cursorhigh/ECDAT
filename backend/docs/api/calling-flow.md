# ECDAT API — Calling Flow

The happy path end-to-end, in the order a client or an automation pipeline
should call the API. All calls use the envelope (see [README.md](README.md));
this document shows the `data` portion with the API key header implied:

```
X-API-Key: ecdat_<prefix>_<secret>
```

## 0. Provision

Create the keys once on the server:

```
cd backend
venv\Scripts\python manage.py create_api_key "pipeline"
# -> ecdat_…_…   (printed once; never stored as plaintext)
venv\Scripts\python manage.py create_api_key --list
```

## 1. Start on a clean scope

A work session keeps discovery + analysis data isolated. Create (or reuse) one
and keep its cookie/id for the whole run:

```http
POST /api/session/create/
Content-Type: application/json

{ "data": { "name": "2026-Q4 floor-sweep" } }
```

Responds with `{ "id": …, "name": …, "created": true }` and sets the
`ecdat_session_id` cookie. Subsequent requests either carry that cookie or the
explicit id:

```http
GET /api/session/info/
X-ECDAT-Session: 42
```

## 2. Discover

**Local folder scan** — queue a scan of a directory and remember the session it
created (a scan auto-creates its own session when none is active):

```http
POST /api/start-scan/
Content-Type: application/json
X-ECDAT-Session: 42

{ "data": {
    "scan_type": "specified",
    "source_type": "source_code",
    "target": "D:/eng/repos/acme",
    "options": { }
} }
# -> 201 { "id": 7, "status": "queued"|"running", "session": { "id": 42, "name": … } }
```

Poll until the job finishes:

```http
GET /api/scans/7/
# -> data.status == "completed"
```

Or use the demo dataset instead: `POST /api/run-demo-scan/`.

**External scanner data** — skip the folder walk and hand raw findings directly:

```http
POST /api/scan-data/
Content-Type: application/json

{ "data": {
    "source_type": "source_code",
    "target": "acme-widgets",
    "findings": [ { "…": "raw finding shape (see discovery/scanners/base.py)" } ]
} }
# -> 201 { "id": 8, "status": …, "session": { … } }
```

Either route runs the normalizer → parser → correlator pipeline. Track KPIs:

```http
GET /api/stats/
GET /api/scans/?ordering=created_at
GET /api/assets/?search=acme
```

## 3. Analyze

Only completed scans analyze:

```http
POST /api/analysis/start/
Content-Type: application/json
X-ECDAT-Session: 42

{ "data": { "scan_job": 7, "max_findings": 300 } }
# -> 201 { "id": 3, "status": "queued", "progress": 0 }
```

The run is asynchronous. It may pause at an `AWAITING_CONTEXT` decision
(auto-analysis prompt):

```http
GET /api/analysis/awaiting/
# -> [{ "id": 3, "scan_job_id": 7, "seconds_left": 12, … }]
```

If you want to resolve the pause early, re-POST `start` with your chosen
context (`raw_system_context`) — it commits to the existing run rather than
creating a duplicate. Otherwise the run auto-continues with the default.

Check progress, then read the full report:

```http
GET /api/analysis/3/
# -> data.status: "completed"; data.assessments[], data.executive_summary,
#    data.summary_rows[] (risk + migration_priority sorted), data.cbom
```

## 4. Prioritize & mitigate

Completed runs can spawn a mitigation plan:

```http
POST /api/mitigation/run/3/generate/
# -> 201 { "id": 1, "status": "queued", "summary": { "assets": 41, "urgent": 12, … } }
```

Poll the plan until `COMPLETE`, then read the full document:

```http
GET /api/mitigation/1/
# -> data.document { summary, blast_radius, effort, per-asset remediation, … }
```

Overview of the estate's remediation posture:

```http
GET /api/mitigation/overview/
# -> { "totals": { "plans", "assets", "urgent", "quantum_vulnerable", "hndl_exposed" },
#      "runs_unguarded": [ … ] }
```

## 5. Report

The full-pipeline enterprise report is generated on demand:

```http
GET /api/reporting/overview/
# -> KPIs, risk_split[], vuln_priorities[], workflow[]
```

```http
GET /api/reports/full.json   (POST)
# -> { "b64": "…", "filename": "…", "mime": "application/pdf",
#      "format": "pdf", "scope": "session: 42" }
```

For automation, pull the structured snapshot instead:

```http
GET /api/reports/assets.json
GET /api/reports/raw.csv
GET /api/reports/normalized.csv
```

## 6. Audit trail

Every meaningful action is logged and queryable:

```http
GET /api/session/audit/?limit=200
# -> { "count": …, "entries": [ { action, message, actor, session_id, created_at } ] }
```

## Summary of invariants

- All write endpoints accept `{"data": …}`-wrapped or raw bodies.
- Errors: `400` = you gave a bad request (invalid JSON, missing field, wrong
  status/state), `401` = API key missing/invalid/revoked, `404` = object not in
  scope/does not exist, `409` = already queued/conflicting state.
- Long-running work (scan, analysis, mitigation) is asynchronous: create it,
  then poll `status`/`progress` until terminal (`completed` / `cancelled` /
  `failed`).
- Everything is scoped to the active work session (`X-ECDAT-Session`); omit it
  to operate across "All data".