"""Discovery orchestration services (Segment A).

Runs the full pipeline for a ScanJob:
    scanner.run() -> ingest raw -> normalize -> classify -> correlate

Scans are dispatched through the same executor rule as the analysis and
mitigation stages (daemon thread by default, huey when ECDAT_QUEUE_ASYNC=1),
so a running scan can be cancelled at any time and stuck jobs recover on
startup (see sweep_pending_scans).
"""

import os
import threading

from django.conf import settings
from django.utils import timezone
from huey.contrib.djhuey import db_task

from core.models import log_action
from .classifier import classify_asset
from .correlation import build_correlations
from .models import CryptoAsset, RawFinding, ScanJob
from .normalizer import normalize_finding
from .scanners import get_scanner

# Supported discovery scan scopes.
SCAN_TYPES = ("quick", "whole", "specified")


class ScanCancelled(Exception):
    """Raised inside run_scan when the job is cancelled mid-flight."""


def _scan_is_cancelled(scan_job: ScanJob, db: str) -> bool:
    """True once the job row has been flipped to cancelled (by any request)."""
    return (
        ScanJob.objects.using(db)
        .filter(pk=scan_job.pk, status=ScanJob.Status.CANCELLED)
        .exists()
    )


def run_scan(scan_job: ScanJob) -> ScanJob:
    """Execute a scan job end to end and return it."""
    if scan_job.status in (ScanJob.Status.COMPLETED, ScanJob.Status.CANCELLED, ScanJob.Status.RUNNING):
        return scan_job

    db = scan_job._state.db or "default"

    scan_job.status = ScanJob.Status.RUNNING
    scan_job.progress = 5
    scan_job.started_at = timezone.now()
    scan_job.save(using=db, update_fields=["status", "progress", "started_at"])

    log_action(
        "scan_created",
        f"Starting {scan_job.source_type} scan on {scan_job.target}",
        "scanjob",
        scan_job.pk,
        mode=scan_job.mode,
    )

    try:
        scanner = get_scanner(scan_job)
        raw_findings = scanner.run()

        scan_job.progress = 30
        scan_job.save(using=db, update_fields=["progress"])
        ingested = scanner.ingest(raw_findings)

        scan_job.progress = 60
        scan_job.save(using=db, update_fields=["progress"])

        # Normalize + classify each raw finding (all inside the same DB).
        # Cancellation is honoured between findings so a user's cancel lands
        # promptly even on a huge scan.
        qs = RawFinding.objects.using(db).filter(scan_job=scan_job).select_related("normalized")
        for raw in qs.iterator():
            if _scan_is_cancelled(scan_job, db):
                raise ScanCancelled(scan_job.pk)
            norm = normalize_finding(raw, using=db, session_id=scan_job.session_id)
            classify_asset(norm, using=db, session_id=scan_job.session_id)

        scan_job.progress = 90
        scan_job.save(using=db, update_fields=["progress"])

        build_correlations(
            using=db,
            assets=CryptoAsset.objects.using(db).filter(session_id=scan_job.session_id),
        )

        scan_job.status = ScanJob.Status.COMPLETED
        scan_job.progress = 100
        scan_job.finished_at = timezone.now()
        scan_job.save(using=db, update_fields=["status", "progress", "finished_at"])

        log_action(
            "scan_completed",
            f"Scan {scan_job.source_type} complete: {ingested} raw findings",
            "scanjob",
            scan_job.pk,
            mode=scan_job.mode,
        )
        log_action(
            "findings_ingested",
            f"Ingested {ingested} raw findings",
            "scanjob",
            scan_job.pk,
            mode=scan_job.mode,
        )

        _post_ingest(scan_job, db, scan_job.source_type, session_id=scan_job.session_id)
    except ScanCancelled:
        scan_job.status = ScanJob.Status.CANCELLED
        scan_job.progress = 0
        scan_job.error = "Cancelled by user"
        scan_job.finished_at = timezone.now()
        scan_job.save(using=db, update_fields=["status", "progress", "error", "finished_at"])
        log_action("scan_cancelled", f"Scan {scan_job.source_type} cancelled",
                   "scanjob", scan_job.pk, mode=scan_job.mode)
    except Exception as exc:  # noqa: BLE001
        scan_job.status = ScanJob.Status.FAILED
        scan_job.progress = 0
        scan_job.error = str(exc)
        scan_job.finished_at = timezone.now()
        scan_job.save(using=db, update_fields=["status", "progress", "error", "finished_at"])
        log_action("system", f"Scan failed: {exc}", "scanjob", scan_job.pk, mode=scan_job.mode)

    return scan_job


def run_demo_scan() -> ScanJob:
    """Create and run the demo-mode source-code scan in the demo database."""
    from django.conf import settings
    from core import modes
    from core.models import Mode

    if not settings.ECDAT.get("DEMO_MODE"):
        raise RuntimeError("Demo mode is disabled.")

    job = ScanJob.objects.using(modes.DEMO_DB).create(
        source_type=ScanJob.SourceType.SOURCE_CODE,
        target="demo:enterprise-encryption",
        mode=Mode.DEMO,
        status=ScanJob.Status.QUEUED,
    )
    log_action("demo_seeded", "Running demo enterprise crypto scan", "scanjob", job.pk, mode=Mode.DEMO)
    return run_scan(job)


# ---------------------------------------------------------------------------
# Dispatch + cancellation (mirrors analysis/mitigation execution rules)
# ---------------------------------------------------------------------------


def _dispatch_scan(scan_job: ScanJob, db: str) -> ScanJob:
    """Run a queued scan through the configured executor.

    Daemon thread by default (plain runserver); ECDAT_QUEUE_ASYNC=1 routes
    through huey for the dedicated worker. Returns the job unchanged.
    """
    mode = scan_job.mode
    if os.environ.get("ECDAT_QUEUE_ASYNC") == "1":
        run_scan_task(scan_job.pk, mode)
    elif settings.HUEY.get("immediate"):
        run_scan_task(scan_job.pk, mode)
    else:
        threading.Thread(
            target=run_scan_safe,
            args=(scan_job.pk, mode),
            daemon=True,
        ).start()
    return scan_job


def run_scan_by_pk(scan_job_id: int, mode: str) -> ScanJob | None:
    """Load a scan job from its mode DB and run the full pipeline."""
    from core.modes import db_alias_for_mode

    db = db_alias_for_mode(mode)
    job = ScanJob.objects.using(db).filter(pk=scan_job_id).first()
    if job is None:
        return None
    return run_scan(job)


def run_scan_safe(scan_job_id: int, mode: str) -> None:
    """Thread-safety wrapper: run a scan but never let it kill the thread."""
    from django.db import close_old_connections

    try:
        run_scan_by_pk(scan_job_id, mode)
    except Exception as exc:  # noqa: BLE001 - worker thread must survive
        import logging

        logging.getLogger("discovery").exception("run_scan(%s, %s) crashed: %s", scan_job_id, mode, exc)
    finally:
        close_old_connections()


@db_task()
def run_scan_task(scan_job_id: int, mode: str):
    """Thin huey task wrapper around run_scan; never crashes the worker."""
    try:
        run_scan_by_pk(scan_job_id, mode)
    except Exception as exc:  # noqa: BLE001 - worker must survive unexpected errors
        import logging

        logging.getLogger("discovery").exception(
            "run_scan_task: scan %s (mode=%s) crashed: %s", scan_job_id, mode, exc
        )


def cancel_scan_job(scan_job: ScanJob) -> bool:
    """Cancel a scan job (compare-and-swap) and return True if it won the race.

    Only queued/running scans are cancelled; completed, failed or already
    cancelled jobs are left untouched (returns False). The running worker
    thread picks the cancelled state up at the next interrupt check and
    aborts cleanly.
    """
    db = scan_job._state.db or "default"
    won = (
        ScanJob.objects.using(db)
        .filter(
            pk=scan_job.pk,
            status__in=[ScanJob.Status.QUEUED, ScanJob.Status.RUNNING],
        )
        .update(
            status=ScanJob.Status.CANCELLED,
            progress=0,
            error="Cancelled by user",
            finished_at=timezone.now(),
        )
    )
    if not won:
        return False

    scan_job.status = ScanJob.Status.CANCELLED
    scan_job.progress = 0
    scan_job.error = "Cancelled by user"
    scan_job.finished_at = timezone.now()
    log_action("scan_cancelled", f"Scan {scan_job.source_type} cancelled by user",
               "scanjob", scan_job.pk, mode=scan_job.mode)
    return True


def sweep_pending_scans() -> int:
    """Recover scan jobs a previous process left queued/running.

    Called at startup (run_all.sh / run_huey boot): any ScanJob that is still
    QUEUED or RUNNING is stale (the web server isn't accepting requests yet
    when the sweep runs). Reset to QUEUED, clear partial findings, and
    re-dispatch so the scan completes. Returns the number of jobs re-queued.
    """
    from core import modes as modes_mod

    recovered = 0
    for mode in modes_mod.MODES:
        db = modes_mod.db_alias_for_mode(mode)
        stuck = list(
            ScanJob.objects.using(db)
            .filter(
                status__in=[ScanJob.Status.QUEUED, ScanJob.Status.RUNNING],
            )[:200]
        )
        for job in stuck:
            _requeue_scan(job, db)
            recovered += 1
    return recovered


def _requeue_scan(job: ScanJob, db: str) -> None:
    """Reset one stuck scan to queued, clear partial findings, re-dispatch."""
    # Partial results from a crashed scan are junk; drop them before a clean run.
    for raw in RawFinding.objects.using(db).filter(scan_job=job).iterator():
        try:
            if hasattr(raw, "normalized") and raw.normalized_id:
                raw.normalized.delete(using=db)
        except Exception:  # noqa: BLE001 - best-effort cleanup
            pass
        raw.delete(using=db)
    job.status = ScanJob.Status.QUEUED
    job.progress = 0
    job.error = ""
    job.started_at = None
    job.finished_at = None
    job.findings_count = 0
    job.save(using=db, update_fields=["status", "progress", "error", "started_at",
                                      "finished_at", "findings_count"])
    log_action("scan_requeued", f"Re-queued stuck scan {job.pk} to complete it",
               "scanjob", job.pk, mode=job.mode)
    # Enqueue on the persistent huey queue (like the analysis/plan sweeps) so
    # the worker survives; `_dispatch_scan`'s thread branch would be killed
    # when this CLI command exits and the scan would stay queued forever.
    run_scan_task(job.pk, job.mode)


class ScanInspectionError(ValueError):
    """Raised when the user-supplied scan parameters are invalid."""


def create_and_run_scan(source_type: str, target: str = "", config: dict | None = None,
                        mode: str | None = None, scan_type: str = "specified",
                        session_id: int | None = None) -> ScanJob:
    """Create and run a scan with user-supplied parameters.

    `scan_type` selects the scope of the run:
      - "quick"     -> fast scan of the current working directory
      - "whole"     -> scan the entire system
      - "specified" -> scan the folder given in `target`

    The ScanJob is created inside `mode`'s database (defaults to the active
    mode) so the demo/actual data boundary is preserved. `session_id`
    scopes the whole scan (job, findings, assets) to a work session.
    """
    from core import modes as modes_mod
    from core.models import Mode

    source_type = (source_type or "").strip()
    target = (target or "").strip()
    scan_type = (scan_type or "specified").strip()

    if source_type not in ScanJob.SourceType.values:
        raise ScanInspectionError(f"Unknown source type '{source_type}'.")

    if scan_type not in SCAN_TYPES:
        raise ScanInspectionError(f"Unknown scan type '{scan_type}'.")

    if scan_type == "quick":
        target = target or "quick"
    elif scan_type == "whole":
        target = target or "whole"
    elif not target:
        raise ScanInspectionError("Choose a folder to scan.")

    chosen_mode = mode or modes_mod.active_mode()
    db = modes_mod.db_alias_for_mode(chosen_mode)

    scan_config = dict(config or {})
    scan_config["scan_type"] = scan_type
    job = ScanJob.objects.using(db).create(
        source_type=source_type,
        target=target,
        mode=chosen_mode,
        config=scan_config,
        status=ScanJob.Status.QUEUED,
        session_id=session_id,
    )
    log_action("scan_created", f"Queued {source_type} scan on {target}", "scanjob", job.pk, mode=chosen_mode)
    return _dispatch_scan(job, db)


def ingest_external_findings(source_type: str, findings: list[dict], target: str = "",
                             mode: str | None = None,
                             session_id: int | None = None) -> ScanJob:
    """Create a ScanJob and ingest raw findings supplied directly as JSON data.

    This is the "accept calls with data to scan" entry point: a scanner can
    push already-extracted artefact findings (rather than have ECDAT walk a
    local folder). Each `findings` element is a raw finding dict (see
    scanners/base.py / demo.py for the schema). The normalizer/classifier/
    correlator run exactly as they would for a folder scan. `session_id`
    scopes the ingest (job + findings + assets) to a work session.
    """
    from core import modes as modes_mod

    source_type = (source_type or "").strip() or ScanJob.SourceType.SOURCE_CODE

    if source_type not in ScanJob.SourceType.values:
        raise ScanInspectionError(f"Unknown source type '{source_type}'.")

    if not isinstance(findings, list):
        raise ScanInspectionError("`findings` must be a list of raw finding objects.")

    chosen_mode = mode or modes_mod.active_mode()
    db = modes_mod.db_alias_for_mode(chosen_mode)
    job = ScanJob.objects.using(db).create(
        source_type=source_type,
        target=(target or "").strip() or "external-data",
        mode=chosen_mode,
        config={"external": True},
        status=ScanJob.Status.QUEUED,
        session_id=session_id,
    )
    log_action("scan_created", f"Ingesting {len(findings)} external findings ({source_type})",
               "scanjob", job.pk, mode=chosen_mode)

    # Persist the raw findings (same behaviour as a scanner's ingest()).
    job.status = ScanJob.Status.RUNNING
    job.progress = 5
    job.started_at = timezone.now()
    job.save(using=db, update_fields=["status", "progress", "started_at"])

    count = 0
    for item in findings:
        if _scan_is_cancelled(job, db):
            job.status = ScanJob.Status.CANCELLED
            job.error = "Cancelled by user"
            job.finished_at = timezone.now()
            job.save(using=db, update_fields=["status", "error", "finished_at"])
            log_action("scan_cancelled", f"External ingest ({source_type}) cancelled",
                       "scanjob", job.pk, mode=chosen_mode)
            return job
        RawFinding.objects.using(db).create(
            scan_job=job,
            mode=chosen_mode,
            source_type=source_type,
            location=(item or {}).get("location", ""),
            raw_json=item or {},
            session_id=session_id,
        )
        count += 1
    job.findings_count = count
    job.save(using=db, update_fields=["findings_count"])

    # Reuse the shared post-ingest processing (normalize -> classify -> correlate).
    _post_ingest(scan_job=job, db=db, source_type=source_type, session_id=session_id)
    return job


def _post_ingest(scan_job: ScanJob, db: str, source_type: str,
                 session_id: int | None = None) -> None:
    """Normalize + classify every raw finding, then build correlations.

    Honours a user-initiated cancellation between findings (the job is marked
    cancelled and processing stops) so external data ingests — which run
    inline in their caller — stay cancellable too.
    """
    qs = RawFinding.objects.using(db).filter(scan_job=scan_job).select_related("normalized")
    for raw in qs.iterator():
        if _scan_is_cancelled(scan_job, db):
            scan_job.status = ScanJob.Status.CANCELLED
            scan_job.error = "Cancelled by user"
            scan_job.finished_at = timezone.now()
            scan_job.save(using=db, update_fields=["status", "error", "finished_at"])
            log_action("scan_cancelled", f"Scan {source_type} cancelled",
                       "scanjob", scan_job.pk, mode=scan_job.mode)
            return
        norm = normalize_finding(raw, using=db, session_id=session_id)
        classify_asset(norm, using=db, session_id=session_id)

    build_correlations(
        using=db,
        assets=CryptoAsset.objects.using(db).filter(session_id=session_id),
    )

    scan_job.status = ScanJob.Status.COMPLETED
    scan_job.progress = 100
    scan_job.finished_at = timezone.now()
    scan_job.save(using=db, update_fields=["status", "progress", "finished_at"])
    log_action("scan_completed",
               f"Scan {source_type} complete: {scan_job.findings_count} raw findings",
               "scanjob", scan_job.pk, mode=scan_job.mode)

    _auto_analyze(scan_job)


def _auto_analyze(scan_job) -> None:
    """Once processing is done, stage analysis for a context choice (opt-out via env).

    The run is created awaiting the user's context choice (default context
    auto-continues after the configurable timeout) — opt out by setting
    ECDAT_AUTO_ANALYSE=0.
    """
    import os

    if os.environ.get("ECDAT_AUTO_ANALYSE", "1") == "0":
        return

    from core.models import Mode

    if scan_job.mode == Mode.DEMO:
        return

    from discovery.models import NormalizedFinding

    db = scan_job._state.db or "default"
    if scan_job.findings_count <= 0 and not (
        NormalizedFinding.objects.using(db).filter(raw_finding__scan_job=scan_job).exists()
    ):
        return

    from analysis.models import AnalysisRun

    if AnalysisRun.objects.using(db).filter(
        scan_job=scan_job,
        status__in=[
            AnalysisRun.Status.AWAITING_CONTEXT,
            AnalysisRun.Status.QUEUED,
            AnalysisRun.Status.RUNNING,
        ],
    ).exists():
        return

    from analysis.runner import pending_analysis

    pending_analysis(scan_job)
