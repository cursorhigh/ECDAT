"""Discovery orchestration services (Segment A).

Runs the full pipeline for a ScanJob:
    scanner.run() -> ingest raw -> normalize -> classify -> correlate
"""

from django.utils import timezone

from core.models import log_action
from .classifier import classify_asset
from .correlation import build_correlations
from .models import RawFinding, ScanJob
from .normalizer import normalize_finding
from .scanners import get_scanner

# Supported discovery scan scopes.
SCAN_TYPES = ("quick", "whole", "specified")


def run_scan(scan_job: ScanJob) -> ScanJob:
    """Execute a scan job end to end and return it."""
    if scan_job.status == ScanJob.Status.COMPLETED:
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
        qs = RawFinding.objects.using(db).filter(scan_job=scan_job).select_related("normalized")
        for raw in qs.iterator():
            norm = normalize_finding(raw, using=db)
            classify_asset(norm, using=db)

        scan_job.progress = 90
        scan_job.save(using=db, update_fields=["progress"])

        build_correlations(using=db)

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


class ScanInspectionError(ValueError):
    """Raised when the user-supplied scan parameters are invalid."""


def create_and_run_scan(source_type: str, target: str = "", config: dict | None = None,
                        mode: str | None = None, scan_type: str = "specified") -> ScanJob:
    """Create and run a scan with user-supplied parameters.

    `scan_type` selects the scope of the run:
      - "quick"     -> fast scan of the current working directory
      - "whole"     -> scan the entire system
      - "specified" -> scan the folder given in `target`

    The ScanJob is created inside `mode`'s database (defaults to the active
    mode) so the demo/actual data boundary is preserved.
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
    job = ScanJob.objects.using(db).create(
        source_type=source_type,
        target=target,
        mode=chosen_mode,
        config=config or {},
        status=ScanJob.Status.QUEUED,
    )
    log_action("scan_created", f"Queued {source_type} scan on {target}", "scanjob", job.pk, mode=chosen_mode)
    return run_scan(job)
