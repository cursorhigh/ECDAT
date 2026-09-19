"""Crypto-discovery scan pipeline: huey tasks + orchestration.

Design rules (from the spec):
- DB rows are authoritative; huey/queue state is disposable.
- All tasks are idempotent: they can be run multiple times safely.
- Chunk tasks mark themselves running -> done and store YARA matches in
  ScanChunk.results (capped; no full file dumps).
- check_scan_complete marks the Scan complete when every chunk is done, then
  triggers report aggregation.

Wiring into discovery inventory
-------------------------------
When an async Scan completes, its aggregated findings are forwarded into the
`discovery` pipeline via `discovery.services.ingest_external_findings(...)` so
real async scans populate the crypto asset inventory (the dashboard's source).

Mode note: the `crypto_scan` app is exempt from the demo/actual split (the DB
router always routes crypto_scan models to `default`), so real async scan data
belongs in the `actual` mode. We therefore always ingest with mode="actual".

Idempotency: `_scan_complete_check` can re-fire (task path + crash sweep).
The `Scan.ingested_at` guard ensures we forward aggregated findings only once.
"""

import logging
from datetime import timedelta

from django.utils import timezone
from huey.contrib.djhuey import db_task

from .models import Scan, ScanChunk

logger = logging.getLogger("crypto_scan")

# A chunk stuck 'running' longer than this is assumed crashed and reset.
STALE_MINUTES = 5

# Cap how much context is retained per finding (no full file dumps).
MAX_CONTEXT_LINES = 20
MAX_FINDINGS_PER_CHUNK = 5000

# YARA rule name -> explicit discovery family. Unknown families are left to the
# normalizer's algorithm guess; the benign cases are pinned exactly so that
# classification stays accurate for common crypto artefacts.
_RULE_FAMILY = {
    "Crypto_RSA": "rsa",
    "Crypto_ECC": "ecc",
    "Crypto_AES": "aes",
    "Crypto_Hash": "hash",
    "Crypto_WeakHash_MD5": "hash",
    "Crypto_PostQuantum": "pqc",
}


def _to_raw_finding(f: dict) -> dict:
    """Adapt an aggregated crypto_scan finding into a discovery raw finding.

    Discovery's normalizer derives the family from `family`/`algorithm` keys;
    we set an explicit family for well-known rules and carry over protocol /
    library metadata so classification stays accurate.
    """
    rule = f.get("rule", "")
    family = _RULE_FAMILY.get(rule, "")
    raw = {
        "location": f.get("file", ""),
        "family": family,
        "algorithm": f.get("algorithm", ""),
        "confidence": 0.7,
    }
    if rule == "Crypto_TLS":
        raw["protocol"] = "TLS"
    elif rule == "Crypto_Library_BoringSSL":
        raw["library"] = "BoringSSL"
    raw["raw"] = f
    return raw


def _cap_context(finding: dict) -> dict:
    """Cap the 'context' of a finding to MAX_CONTEXT_LINES entries."""
    if not isinstance(finding, dict):
        return finding
    ctx = finding.get("context")
    if isinstance(ctx, list) and len(ctx) > MAX_CONTEXT_LINES:
        finding["context"] = ctx[:MAX_CONTEXT_LINES]
    return finding


def _process_file(path: str) -> list[dict]:
    """Run YARA on one file and return per-match findings with capped context."""
    from .yara_engine import match_file

    findings = []
    for m in match_file(path):
        entry = {
            "file": path,
            "rule": m["rule"],
            "algorithm": m.get("algorithm", ""),
            "kind": m.get("kind", ""),
            "matches": m.get("count", 0),
            "strings": m.get("strings", []),
            "context": [],  # reserved for capped surrounding text (not captured)
        }
        findings.append(_cap_context(entry))
    return findings


@db_task()
def scan_chunk(scan_id: int, chunk_id: int, file_paths: list[str]):
    """Process one chunk of a scan with YARA (idempotent)."""
    try:
        chunk = ScanChunk.objects.select_related("scan").get(
            scan_id=scan_id, chunk_id=chunk_id
        )
    except ScanChunk.DoesNotExist:
        logger.warning("scan_chunk: ScanChunk scan=%s chunk=%s missing; skipping",
                       scan_id, chunk_id)
        return

    if chunk.status == ScanChunk.Status.DONE:
        logger.info("scan_chunk: chunk %s/%s already done; idempotent skip",
                    scan_id, chunk_id)
        return

    if chunk.status == ScanChunk.Status.CANCELLED or chunk.scan.status == Scan.Status.CANCELLED:
        logger.info("scan_chunk: chunk %s/%s cancelled; skipping", scan_id, chunk_id)
        return

    ScanChunk.objects.filter(pk=chunk.pk).update(status=ScanChunk.Status.RUNNING)

    results = []
    for i, path in enumerate(file_paths):
        # Honour a user cancel roughly every 16 files (cheap DB check).
        if i % 16 == 0 and Scan.objects.filter(
            pk=scan_id, status=Scan.Status.CANCELLED
        ).exists():
            ScanChunk.objects.filter(pk=chunk.pk).update(
                status=ScanChunk.Status.CANCELLED, updated_at=timezone.now()
            )
            logger.info("scan_chunk: scan %s cancelled; chunk %s abandoned", scan_id, chunk_id)
            return
        try:
            results.extend(_process_file(path))
        except Exception as exc:  # noqa: BLE001 - keep scanning remaining files
            logger.warning("scan_chunk: error scanning %s: %s", path, exc)
        if len(results) >= MAX_FINDINGS_PER_CHUNK:
            break

    # A cancel that landed after the last loop check must win over DONE.
    if Scan.objects.filter(pk=scan_id, status=Scan.Status.CANCELLED).exists():
        ScanChunk.objects.filter(pk=chunk.pk).update(
            status=ScanChunk.Status.CANCELLED, updated_at=timezone.now()
        )
        return

    ScanChunk.objects.filter(pk=chunk.pk).update(
        status=ScanChunk.Status.DONE,
        results=results,
        updated_at=timezone.now(),
    )
    check_scan_complete(scan_id)


def _scan_complete_check(scan_id: int) -> None:
    """Inner check used by both the task path and the crash-recovery sweep."""
    scan = Scan.objects.filter(pk=scan_id).first()
    if scan is None:
        return
    if scan.status == Scan.Status.CANCELLED:
        return

    total = scan.chunk_count
    done = ScanChunk.objects.filter(scan_id=scan_id, status=ScanChunk.Status.DONE).count()
    if total > 0 and done >= total:
        Scan.objects.filter(pk=scan_id).update(
            status=Scan.Status.COMPLETE, chunk_count=total
        )
        logger.info("scan %s complete (%s/%s chunks); aggregating report",
                    scan_id, done, total)
        aggregate_report(scan_id)
        _forward_to_inventory(scan_id)


def _forward_to_inventory(scan_id: int) -> None:
    """Forward an async Scan's aggregated findings into the discovery inventory.

    Idempotent: only forwarded once per Scan (guarded by `ingested_at`). The
    ingest call is best-effort -- a completed scan must not fail because of an
    inventory hiccup, so failures are logged and never raised.
    """
    scan = Scan.objects.filter(pk=scan_id).first()
    if scan is None:
        return
    if scan.ingested_at is not None:
        return

    findings = aggregate_report(scan_id)
    if not findings:
        return

    # Mark intent before ingesting to avoid a race between the task path and
    # the crash sweep both passing the guard. A rare crash may leave a scan
    # "claimed" but uningested; acceptable for this minimal fix.
    scan.ingested_at = timezone.now()
    scan.save(update_fields=["ingested_at"])

    try:
        from segments.scraping.discovery.services import ScanInspectionError, ingest_external_findings

        adapted = [_to_raw_finding(f) for f in findings]
        ingest_external_findings(
            source_type="source_code",
            findings=adapted,
            target=scan.path or f"scan-{scan.pk}",
            mode="actual",
            session_id=scan.session_id,
        )
        logger.info("scan %s forwarded %s finding(s) into discovery inventory",
                    scan_id, len(adapted))
    except ScanInspectionError as exc:
        logger.warning("scan %s: inventory ingest rejected (%s)", scan_id, exc)
    except Exception as exc:  # noqa: BLE001 - scan is already complete
        logger.warning("scan %s: inventory ingest failed: %s", scan_id, exc)


def check_scan_complete(scan_id: int) -> bool:
    """Compare done-chunk count vs total; marks Scan complete if all done.

    Returns True when the scan is fully complete.
    """
    _scan_complete_check(scan_id)
    scan = Scan.objects.filter(pk=scan_id).first()
    if scan is None:
        return False
    return scan.status == Scan.Status.COMPLETE


def _queryset_chunk_iterator(scan_id: int):
    """Generator yielding raw chunk results for aggregation."""
    qs = ScanChunk.objects.filter(scan_id=scan_id, status=ScanChunk.Status.DONE)
    for chunk in qs.iterator(chunk_size=200):
        for finding in chunk.results:
            if isinstance(finding, dict):
                yield finding


def aggregate_report(scan_id: int) -> list[dict]:
    """Merge all chunk results into a single deduped findings list (stub).

    Dedup key: (file, rule) -> merge counts. Context per finding is capped.
    Intended to be replaced/extended (e.g. by a PQC security-level assessor).
    """
    dedup: dict[tuple, dict] = {}
    order: list[tuple] = []

    for finding in _queryset_chunk_iterator(scan_id):
        key = (finding.get("file", ""), finding.get("rule", ""))
        if key in dedup:
            dedup[key]["files_count"] = (dedup[key].get("files_count") or 0) + 1
            continue
        dedup[key] = _cap_context(dict(finding))
        order.append(key)

    return [dedup[k] for k in order]


def sweep_stale_chunks():
    """Reset ScanChunks stuck in 'running' for >STALE_MINUTES back to 'pending'
    and re-enqueue them. Intended for the huey worker startup path.

    Chunks of user-cancelled scans are never resurrected by the sweep.
    """
    cutoff = timezone.now() - timedelta(minutes=STALE_MINUTES)
    stale = ScanChunk.objects.filter(
        status=ScanChunk.Status.RUNNING,
        scan__status__in=[Scan.Status.RUNNING, Scan.Status.PENDING],
        updated_at__lt=cutoff,
    )
    scan_ids = set(stale.values_list("scan_id", flat=True))
    retried = stale.count()
    stale.update(status=ScanChunk.Status.PENDING)
    for scan_id in scan_ids:
        _requeue_pending_chunks(int(scan_id))
    if retried:
        logger.info("sweep: reset %s stale chunk(s) to pending", retried)
    return retried


def _requeue_pending_chunks(scan_id: int) -> int:
    """Enqueue a huey task for every pending chunk of a scan. Returns count."""
    scan = Scan.objects.filter(pk=scan_id).first()
    if scan is None or scan.status == Scan.Status.CANCELLED:
        return 0
    chunk_ids = list(
        ScanChunk.objects.filter(
            scan_id=scan_id, status=ScanChunk.Status.PENDING
        ).values_list("chunk_id", flat=True)
    )
    if not chunk_ids:
        return 0

    # Load the file list. We store it only inside the Scan config for
    # re-enqueue; a lightweight approach is to persist paths on the chunk.
    # For crash recovery we reconstruct file_paths from scan.path + chunk.
    files_by_chunk = _load_chunk_file_paths(scan_id, chunk_ids, scan)
    for cid in chunk_ids:
        scan_chunk(scan_id, cid, files_by_chunk.get(cid, []))
    return len(chunk_ids)


def _load_chunk_file_paths(scan_id: int, chunk_ids: list[int],
                           scan: "Scan | None") -> dict[int, list[str]]:
    """Reconstruct each chunk's file_paths for re-enqueue.

    We don't persist the file list per chunk, so we recompute the chunked
    split from the scan path deterministically (same splitter as start_scan).
    """
    from .fs import split_paths_into_chunks, walk_scan_files

    if scan is None:
        return {}
    try:
        all_paths = list(walk_scan_files(scan.path))
    except Exception as exc:  # noqa: BLE001
        logger.warning("sweep: cannot recompute files for scan %s: %s", scan_id, exc)
        return {}
    nchunks = scan.chunk_count or max(1, len(chunk_ids))
    chunks = split_paths_into_chunks(all_paths, nchunks)
    return {cid: chunks[cid] for cid in chunk_ids if cid < len(chunks)}
