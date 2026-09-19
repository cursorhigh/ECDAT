# Segments/ml — ML & agents

Owns the analysis layer: turning a scan's findings into a CBOM, classifying
risk, threat-analysis (HNDL) and Mosca/quantum-vulnerability scoring.

## Django app

- **`analysis/`** — models `AnalysisRun` (+ `AssetAssessment`), the pipeline
  runner (`runner.py`), payload builder, and the `/api/analysis/` endpoints.

## Agent packages (pure Python, no Django)

- **`cbom/`** — CBOM generation, builder, validator, explainability, LLM providers.
- **`hndl/`** — HNDL threat analysis plus terminal report formatter.
- **`risk_agent/`** — quantum-risk classification.
- **`mosca_agent/`** — Mosca inequality scoring, crypto rules, exceptions.
- (see also `segments/ml/ML_pipe/`, a git-ignored experimental folder.)

These packages carry their own `unittest` files (e.g. `hndl/test_hndl.py`).

## Schema owned here

`AnalysisRun`, `AssetAssessment` — see
`docs/architecture/schema-ownership.md`.

## Handoff

Consumes scraping findings (contract `schema/contracts/raw_finding.py`);
emits the CBOM + risk context (contract `schema/contracts/cbom_payload.py`)
that `mitigation` turns into a plan.

```bash
make test-ml
```