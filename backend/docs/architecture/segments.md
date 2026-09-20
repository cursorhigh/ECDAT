# ECDAT segment architecture

ECDAT is a **bounded-context modular monolith** (a single Django application,
one deployable). The codebase is physically split into four **workstream
segments** so each team owns a visible folder, plus a small shared core.

```
config/                         shared infra: settings, URLs, DB router, wsgi/asgi
core/                           shared core: Mode/WorkSession/AuditLog, sessions,
                                middleware, context processors, `sweep_pending`
segments/
  scraping/                     Ingestion & scanning team
    discovery/                  Django app — ScanJob, RawFinding, NormalizedFinding,
                                CryptoAsset, AssetRelation, scanners, ingest API
    crypto_scan/                Django app — Scan/ScanChunk YARA FS pipeline (default DB),
                                huey consumer setup (`run_huey`)
  ml/                           ML / agents team
    analysis/                   Django app — AnalysisRun, AssetAssessment, runner, payloads
    cbom/ hndl/ risk_agent/ mosca_agent/   pure-python agent packages
  mitigation/                   Mitigation team
    mitigation/                 Django app — MitigationPlan, planner
    mitigation_agent/           pure-python mitigation agent package
  reporting/                    Reporting & UI team
    dashboard/                  Django app — all server-rendered templates + static
    reports/                    Django app — PDF/HTML/CSV/JSON exports
schema/                         cross-segment data contracts (pydantic) + schema docs
scripts/generate_schema_docs.py schema-visibility generator (ownership matrix + ERD)
```

## Dependency rule (the one real rule)

Segments are independent. Only two exceptions may cross a segment boundary:

1. **Anything may import `core`** (shared infrastructure).
2. `reporting` is the presentation layer: it may read any segment's read models
   and call their *service functions*.

Otherwise a segment must **not** import another segment's internals. Cross-segment
work is handed off via **schema contracts** in `schema/contracts/` and through
owned DB rows, never by importing another segment's module internals.

This rule is enforced with `import-linter` (see `.importlinter`):

```bash
pip install -r requirements-dev.txt
lint-imports
```

## Handoffs (what flows between segments)

| From | To | Contract | Storage |
|---|---|---|---|
| scraping (ingest) | ml | raw/normalized findings | `schema/contracts/raw_finding.py` | `RawFinding`, `NormalizedFinding` rows |
| scraping (inventory) | ml | crypto assets | (part of raw-finding contract) | `CryptoAsset` rows |
| ml (analysis) | mitigation | CBOM + risk assessment | `schema/contracts/cbom_payload.py` | `AnalysisRun` rows |
| mitigation | reporting | mitigation plan document | `schema/contracts/plan_document.py` | `MitigationPlan.document` |
| reporting | user | full report payload | `schema/contracts/report_payload.py` | generated at request time |

## Schema ownership and DB routing

Every table is owned by one segment — see
[`schema-ownership.md`](schema-ownership.md) (auto-generated, together with the
[`ecdat-erd.md`](ecdat-erd.md) ERD, by `scripts/generate_schema_docs.py`).

Each segment's models keep their **own migrations under the segment folder**
(e.g. `segments/ml/analysis/migrations/`), so schema reviews never leave the
team's view. The DB router (`config/db_router.py`) is unchanged: everything
routes to the active mode's database except `crypto_scan`, which always lives
on `default`.

## Running per-segment

Makefile targets (also `make help`):

```bash
make test                 # full suite
make test-scraping        # discovery + crypto_scan
make test-ml              # analysis (+ agent package tests)
make test-mitigation      # mitigation
make test-reporting       # dashboard + reports
make schema-docs          # regenerate ownership matrix + ERD
make lint-imports         # enforce segment boundary rules
```

## Regenerating schema docs

```bash
python scripts/generate_schema_docs.py
```