# Enterprise Cryptographic Discovery & Analysis Tool (ECDAT) — Backend

Django 5 + Django REST Framework. Scanners, normalisation, correlation, the ML
agents, the worker, and the API the console talks to.

For the project as a whole see the [root README](../README.md).

---

## Stack

| | |
|---|---|
| Language | Python 3.12 |
| Framework | Django 5.0.7, Django REST Framework 3.17.2 |
| Database | SQLite by default; PostgreSQL supported (`DB_*` + `psycopg2`) |
| Background work | huey 3.3.4 (in-process by default, worker when `ECDAT_QUEUE_ASYNC=1`) |
| Binary inspection | `yara-python` 4.5.4 |
| LLM providers | Google Gemini (`google-genai`), OpenAI — all optional |

Pinned exactly in `requirements.txt`. The ML stack (`joblib`, `scikit-learn`,
`pytest`) is *not* listed; see [Known limitations](#known-limitations).

## Layout

```
backend/
├── manage.py
├── config/                  settings, root URLconf, DB router, ASGI/WSGI
├── core/                    shared infrastructure
│   ├── models.py            WorkSession, AuditLog, ApiKey, TimeStampedModel
│   ├── sessions.py          scope() — the per-session data boundary
│   ├── middleware.py        session resolution, optional API-key gate
│   ├── modes.py             active mode
│   └── sqlite_pragmas.py    WAL and durability setup
├── segments/                bounded-context modular monolith
│   ├── scraping/
│   │   ├── discovery/       scanners, normalise, correlate, graph  ← the workhorse
│   │   └── crypto_scan/     Scan / ScanChunk, YARA pipeline
│   ├── ml/
│   │   ├── analysis/        AnalysisRun, AssetAssessment, the pipeline runner
│   │   ├── cbom/            CycloneDX + native CBOM generation
│   │   ├── mosca_agent/     cryptographically significant algorithms
│   │   ├── hndl/            harvest-now-decrypt-later
│   │   ├── risk_agent/      risk grading (+ Quantum_Risk_Model)
│   │   └── final_combined_result/
│   ├── mitigation/
│   │   ├── mitigation/      MitigationPlan, wave sequencing
│   │   └── mitigation_agent/
│   └── reporting/
│       ├── reports/         report builder + export
│       └── dashboard/       aggregate metrics
├── schema/contracts/        payloads segments exchange (see below)
├── docs/                    API reference, ERD, segment rules
└── scripts/
```

### The segment rule

ECDAT is a **bounded-context modular monolith**. Each segment owns its own Django
app and its own migrations, so schema changes stay inside the owning team's view.
Any segment may import `core`. Segments do **not** import each other directly —
they exchange the typed payloads in `schema/contracts/`, which is enforced by
import-linter.

Details: [`docs/architecture/segments.md`](docs/architecture/segments.md) and
[`schema/README.md`](schema/README.md).

## Data model

| App | Models |
|---|---|
| `core` | `WorkSession`, `AuditLog`, `ApiKey` |
| `discovery` | `ScanJob`, `ScanBatch`, `RawFinding`, `NormalizedFinding`, `CryptoAsset`, `AssetOccurrence`, `Dependency`, `DependencyRelation`, `AssetRelation`, `GraphNode`, `GraphEdge` |
| `analysis` | `AnalysisRun`, `AssetAssessment` |
| `mitigation` | `MitigationPlan` |
| `crypto_scan` | `Scan`, `ScanChunk` |

Diagram: [`docs/architecture/ecdat-erd.md`](docs/architecture/ecdat-erd.md).

**Two ideas carry most of the design.**

*Scans are hard boundaries.* `core.sessions.scope(qs, session_id)` filters every
queryset to the active `WorkSession`. Scans never share data — not assets, not
findings, not runs. Switching scan in the UI changes every view at once, and
deleting a scan's data leaves its audit trail intact.

*Provenance is preserved to the file.* `RawFinding` keeps the exact location
discovery read from. `NormalizedFinding` is the deduplicated, canonical view.
`CryptoAsset` is the thing that actually exists in the world. Keeping all three
means a normalised claim can always be traced back to the byte that produced it.

## The discovery pipeline

`segments/scraping/discovery/services.py` is the core. `run_scan` walks:

```
dispatch → scan (one job, many scanners) → ingest RawFindings
        → normalise → classify → correlate → build graph
        → write terminal status → stage analysis
```

### One job, many sources

A single scan action creates **one `WorkSession` and one `ScanJob`**. The selected
sources are stored in `ScanJob.config["source_types"]` and every applicable
scanner runs sequentially inside that one job, sharing one set of progress
updates. `source_type` on the job records the primary source only; each finding
keeps its real one.

A source that cannot apply to the target is recorded as a skip reason and excluded
from the findings set — that is a target mismatch, not a defect, and it does not
make the job `partial`.

### Scanners

`segments/scraping/discovery/scanners/` — `binary`, `binary_scanner`,
`certificate_scanner`, `certstore`, `container_image`, `container_scanner`,
`crypto_artefact`, `dependency`, `keymaterial`, `lockfiles`, `platform`,
`sourceapi`, `x509`.

`get_scanner(scan_job, source_type=None)` returns the scanner for a source, or the
job's primary one when no override is given.

### Honesty about coverage

A scan that finishes but could not read everything is `partial`, never `failed`,
and never silently `completed`. The job records `items_scanned`, `items_total`,
`items_skipped` and `skip_reasons`.

`AnalysisRun.coverage` copies that gap onto the assessment, so a report built on
partial evidence states its own limits instead of implying full coverage.

This matters more than it sounds: it is the difference between "we looked at
everything" and "we looked at 115 of 116 files and one was not a format we
recognise".

## Analysis

`segments/ml/analysis/runner.py`.

Statuses: `awaiting_context → queued → running → completed | failed | cancelled`,
plus `paused`.

- **Context first.** Risk grading depends on operational context (is this internet
  facing? how long must the data stay secret?). An unattended run reuses the last
  context a human actually chose in that session, and falls back to conservative
  defaults only when there is nothing to reuse.
- **Pause and resume.** `paused` keeps every assessment already written; resuming
  skips the assets that have one.
- **No artificial caps.** `max_findings` omitted means all findings. When a cap *is*
  set, truncation is declared in the output rather than quietly applied.
- **Partial scans are analysable**, because the scan recorded precisely what it
  missed. Only genuinely unfinished work (queued, running, cancelled) is refused.
- **Staging is non-fatal.** A failure to stage analysis is recorded; it never
  relabels a scan that already finished.

Every LLM call has a deterministic fallback provider, so the pipeline runs with no
API key and is testable offline.

## API

Mounted one prefix per segment:

| Prefix | Segment |
|---|---|
| `/api/health/` | liveness |
| `/api/` | discovery — scans, findings, assets, graph, handoff |
| `/api/analysis/` | runs, start, pause, resume, cancel, CBOM export |
| `/api/mitigation/` | plans and waves |
| `/api/crypto/` | YARA scanning |
| `/api/reports/`, `/api/reporting/` | report building, dashboard metrics |
| `/api/session/` | session create / switch / info |

Reference: [`docs/api/README.md`](docs/api/README.md) ·
[endpoints](docs/api/endpoints.md) · [calling flow](docs/api/calling-flow.md)

Responses are enveloped as `{ success, code, message, data, meta }`.

## Running

```bash
python manage.py migrate
python manage.py runserver 127.0.0.1:8000        # --noreload in scripts
python manage.py test
```

> The backend root also holds a number of **ad-hoc test and pipeline scripts** from
> development (`test_cbom*.py`, `test_full_ecdat_pipeline.py`, `test_mosca_engine.py`,
> `run_*_pipeline.py`, `verify_*.py`). They are run directly rather than through the
> suite, and several assume API keys. They are not part of the supported interface.

Prefer the root launcher, which also starts the worker and the UI:
`./run.sh --mode backend-only`.

## Configuration

Copy `.env.example` to `.env`. Every variable is optional; see the table in the
[root README](../README.md#configuration).

## Tests

```bash
python manage.py test                       # whole suite
python manage.py test segments.ml.analysis  # one segment
```

578 tests. **10 fail and 3 error at `HEAD`** — see
[Known limitations](#known-limitations). None are in the happy path.

The 3 errors are all missing optional dependencies: `joblib` and `pytest` are not in
`requirements.txt`, and `segments.ml.risk_agent.Quantum_Risk_Model.src.predict` does
not exist. Adding the ML stack to `requirements.txt` would clear one of the three.

## Known limitations

- **The suite is not green.** 10 failures, 3 errors, all pre-existing. The errors
  are missing optional dependencies (the ML stack — `joblib`, `pytest`,
  `src.predict` — is absent from `requirements.txt`). The failures are in mitigation
  document generation, the report builder, one discovery library test and one
  crypto invariant. Confirmed pre-existing by running at `HEAD` with no local
  changes.
- **`DJANGO_SECRET_KEY` has an insecure default.** Development only.
- **The API key gate is off in development.** `AuditLog.actor` is then a claimed
  value, not a verified identity.
- **Audit immutability is conventional.** SQLite `DROP TABLE` bypasses the
  triggers.
- **`cloud` and `hsm` source types are modelled but not credentialed.** Scanning
  them needs authorised accounts that are deliberately absent.
- **Secrets exist in git history.** A populated `.env` and a real SQLite database
  were committed before `.gitignore` covered them. Rotate anything in that
  history.
- **RLS-style enforcement is absent.** Session scoping is applied in application
  code, not by the database, so a query that forgets `scope()` leaks across scans.
