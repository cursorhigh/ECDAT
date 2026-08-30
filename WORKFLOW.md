# ECDAT — Data Flow Workflow

Compact end-to-end walk of how a scan's data moves through ECDAT: **request → pipeline → dashboard**.

---

## 1. The whole flow at a glance

```mermaid
flowchart LR
    UI[Discovery UI<br/>startScan()] -->|POST /api/start-scan/| V[start_scan view]
    EXT[Friend scanner /<br/>other tool] -->|POST /api/scan-data/| V2[scan_data view<br/>JSON findings]
    V --> S[create_and_run_scan]
    V2 --> IE[ingest_external_findings]
    S --> REG[get_scanner<br/>SCANNER_REGISTRY]
    REG --> SC[scanner.run()<br/>crypto_artefact.py]
    SC -->|raw finding dicts| ING[ingest]
    IE --> ING
    ING --> RAW[(RawFinding)]
    RAW --> NORM[normalize_finding]
    NORM --> NF[(NormalizedFinding)]
    NF --> CLS[classify_asset]
    CLS --> ASSET[(CryptoAsset)]
    ASSET --> CORR[build_correlations]
    CORR --> REL[(AssetRelation)]
    RAW -.log_action.-> AUDIT[(audit_log)]
    ASSET --> DASH[Dashboard<br/>inventory / graph / risk]
```

Everything downstream of a scanner (`digest → normalize → classify → correlate`) is **shared**, so folder scans, demo scans, and pushed JSON data all hit the same pipeline.

---

## 2. Entry points

| Trigger | Route | View → service |
|---|---|---|
| Manual scan (Discovery UI) | `POST /api/start-scan/` | `start_scan` → `create_and_run_scan` |
| Demo scan | `POST /api/run-demo-scan/` | `run_demo_scan` → `run_scan` |
| External / pushed data | `POST /api/scan-data/` | `scan_data` → `ingest_external_findings` |

The **friend's hook** lives in `discovery/scanners/crypto_artefact.py` → `_extract_artefacts()` (folder walk) or directly via `/api/scan-data/` (push JSON).

---

## 3. Pipeline stages

| # | Stage | Unit | In | Out |
|---|---|---|------|-----|
| 1 | **Request** | `discovery/views.py` | JSON (`target`, `source_type`, `scan_type`, `options`) | `ScanJob` (queued) |
| 2 | **Discover** | `scanners/*` (`crypto_artefact.py`) | `ScanJob` + target folder/data | list of raw-finding dicts |
| 3 | **Ingest** | `scanners/base.py` `ingest()` | raw finding dicts | `RawFinding[]` |
| 4 | **Normalize** | `normalizer.py` | `RawFinding` | `NormalizedFinding` (dedup, confidence) |
| 5 | **Classify** | `classifier.py` | `NormalizedFinding` | `CryptoAsset` |
| 6 | **Correlate** | `correlation.py` | `CryptoAsset[]` | `AssetRelation[]` (graph) |
| 7 | **Audit** | `core/models.py` `log_action()` | pipeline events | audit log |

---

## 4. Data models (the contract)

```
ScanJob ──1:N──> RawFinding ──1:1──> NormalizedFinding ──M:N──> CryptoAsset ──1:N──> AssetRelation
                             (raw_json)                             (from/to edges)
```

| Model | Purpose | Key fields |
|---|---|---|
| **ScanJob** | one scan run | `source_type`, `target`, `status`, `progress`, `config` |
| **RawFinding** | un-normalized output | `location`, `raw_json` (free-form dict) |
| **NormalizedFinding** | canonical, deduped | `family`, `algorithm`, `key_size`, `curve`, `protocol`, `library(_version)`, `confidence` |
| **CryptoAsset** | consolidated asset | `name`, `family`, `algorithm`, `location`, `inventory_status` |
| **AssetRelation** | graph edge | `from_asset`, `to_asset`, `relation_type` |

Raw finding dicts carry `family/algorithm/key_size/curve/protocol/library/library_version/confidence` + any extras (they land verbatim in `raw_json`).

---

## 5. Mode boundary

`mode` (`demo` / `actual`) selects the database via `core.modes.db_alias_for_mode()`; each stage stays in the **same DB** from job to asset, keeping demo data isolated from real data. `DemoScreenshotScanner` is preferred automatically for `demo:` targets.

---

*Companion docs: `ECDAT_PLAN.md` (architecture) · `SETUP.md` (install/run).*
