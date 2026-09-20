# ECDAT shared schema contracts

Cross-segment **handoff contracts**. Each contract names the exact shape of
data handed from one segment to the next so no segment imports another's
internals — it validates and consumes the contract instead.

```
schema/
  notices/
    raw_finding.py        scraping  -> ml     (scan ingest / raw & normalized findings)
    cbom_payload.py       ml        -> mitigation  (CBOM + risk assessment)
    plan_document.py      mitigation -> reporting (mitigation plan document)
    report_payload.py     reporting -> user      (delivered report payload)
```

## Status

These contracts are **documentation-of-record**: they mirror the runtime
structures (see `docs/architecture/schema-ownership.md` and the generated
`ecdat-erd.md`) but the runtime pipeline is **not yet wired to them**.
Adopting a contract in a segment is a small, deliberate step: validate the
payload with `Contract.model_validate(...)` at the producing/consuming
boundary and keep the contract in sync with the schema.

Rules:

- Contracts import **only** `pydantic` (and stdlib) — never Django or segment code.
- Each schema change that touches a handoff must update the matching contract
  and regenerate the schema docs (`python scripts/generate_schema_docs.py`).
- Contracts are owned by the schema boundary; any segment may propose a change,
  but the change must be reviewed by the owning segment (see `CODEOWNERS`).