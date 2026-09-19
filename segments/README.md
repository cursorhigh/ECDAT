# segments/

ECDAT is organized as a bounded-context modular monolith. This directory holds
the four workstream segments — each team owns its folder:

| Folder | Team | Contents |
|---|---|---|
| `scraping/` | Ingestion & scanning | `discovery` + `crypto_scan` Django apps (scanners, normalize, inventory, YARA pipeline) |
| `ml/` | ML / agents | `analysis` Django app + `cbom`, `hndl`, `risk_agent`, `mosca_agent` agent packages |
| `mitigation/` | Mitigation | `mitigation` Django app + `mitigation_agent` package |
| `reporting/` | Reporting & UI | `dashboard` + `reports` Django apps (all templates/static) |

Rules: see `docs/architecture/segments.md`. Any segment may import `core`
(shared infrastructure); otherwise cross-segment work happens through the
contracts in `schema/contracts/` (enforced by import-linter, linted via
`make lint-imports`).

Each segment keeps **its own migrations** under its Django apps, so schema
changes stay inside the owning team's view.