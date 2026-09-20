# Segments/reporting — Reporting & UI

Owns the presentation layer: the full web UI and the exportable reports.

## Django apps

- **`dashboard/`** — all server-rendered pages (templates under
  `dashboard/templates/dashboard/`, static under `dashboard/static/`), the
  chart/HTMX front-end, and the report/preview pages.
- **`reports/`** — enterprise full-pipeline report: HTML snapshot builder
  (`report_builder.py`) and PDF renderer (`pdf_renderer.py`), plus the
  `/reports/` endpoints. PDF is generated on request and never persisted.

## Schema owned here

None — reporting is read-only over the other segments' rows.

## Handoff

Consumes plan documents (contract `schema/contracts/plan_document.py`); emits
the delivered artifact payload (contract `schema/contracts/report_payload.py`).

```bash
make test-reporting
```