# Segments/scraping — Ingestion & scanning

Owns everything that discovers cryptography, from source trees to the crypto
asset inventory.

## Django apps

- **`discovery/`** — models `ScanJob → RawFinding → NormalizedFinding →
  CryptoAsset (+ AssetRelation graph)`, scanners (`scanners/`), normalizer,
  classifier, `services.run_scan` + sweeps, the `/api/` ingest endpoints
  (including the external `/api/scan-data/` intake) and the yara rule engine
  entry point.
- **`crypto_scan/`** — async YARA filesystem pipeline: `Scan`/`ScanChunk`
  models, chunked huey tasks, `run_huey` consumer command. This app always
  migrates to the `default` database (see `config/db_router.py`).

## Schema owned here

`ScanJob`, `RawFinding`, `NormalizedFinding`, `CryptoAsset`, `AssetRelation`
(`discovery`), `Scan`, `ScanChunk` (`crypto_scan`) — see
`docs/architecture/schema-ownership.md`.

## Handoff

Emits findings (contract `schema/contracts/raw_finding.py`) into the `ml`
segment. Run the works:

```bash
make test-scraping
```