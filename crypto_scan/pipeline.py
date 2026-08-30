"""Crypto-discovery scan pipeline: huey tasks + orchestration.

Design rules (from the spec):
- DB rows are authoritative; huey/queue state is disposable.
- All tasks are idempotent: they can be run multiple times safely.
- Chunk tasks mark themselves running -> done and store YARA matches in
  ScanChunk.results (capped; no full file dumps).
- check_scan_complete marks the Scan complete when every chunk is done, then
  triggers report aggregation.
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

    ScanChunk.objects.filter(pk=chunk.pk).update(status=ScanChunk.Status.RUNNING)

    results = []
    for path in file_paths:
        try:
            results.extend(_process_file(path))
        except Exception as exc:  # noqa: BLE001 - keep scanning remaining files
            logger.warning("scan_chunk: error scanning %s: %s", path, exc)
        if len(results) >= MAX_FINDINGS_PER_CHUNK:
            break

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

    total = scan.chunk_count
    done = ScanChunk.objects.filter(scan_id=scan_id, status=ScanChunk.Status.DONE).count()
    if total > 0 and done >= total:
        Scan.objects.filter(pk=scan_id).update(
            status=Scan.Status.COMPLETE, chunk_count=total
        )
        logger.info("scan %s complete (%s/%s chunks); aggregating report",
                    scan_id, done, total)
        aggregate_report(scan_id)


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
    and re-enqueue them. Intended for the huey worker startup path."""
    cutoff = timezone.now() - timedelta(minutes=STALE_MINUTES)
    stale = ScanChunk.objects.filter(
        status=ScanChunk.Status.RUNNING, updated_at__lt=cutoff
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
    scan = Scan.objects.filter(pk=scan_id).first()
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
