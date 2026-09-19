# Segments/mitigation — Mitigation

Owns remediation / migration planning: turning a completed analysis run into a
prioritized, wave-based mitigation plan.

## Django app

- **`mitigation/`** — model `MitigationPlan`, the planner (`planner.py`,
  including auto-trigger on analysis completion and crash-recovery sweeps), and
  the `/api/mitigation/` endpoints.

## Agent package

- **`mitigation_agent/`** — pure-Python mitigation agent (rules, prompts, LLM
  provider) that produces the plan document.

## Schema owned here

`MitigationPlan` — see `docs/architecture/schema-ownership.md`.

## Handoff

Consumes the analysis CBOM (contract `schema/contracts/cbom_payload.py`);
emits the plan document (contract `schema/contracts/plan_document.py`) that
`reporting` renders.

```bash
make test-mitigation
```