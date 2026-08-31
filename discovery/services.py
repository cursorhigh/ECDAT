"""Discovery orchestration services (Segment A).

Runs the full pipeline for a ScanJob:
    scanner.run() -> ingest raw -> normalize -> classify -> correlate
"""

from django.utils import timezone

from core.models import log_action
from .classifier import classify_asset
from .correlation import build_correlations
from .models import CryptoAsset, RawFinding, ScanJob
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
    return run_scan(job)


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
    """Normalize + classify every raw finding, then build correlations."""
    qs = RawFinding.objects.using(db).filter(scan_job=scan_job).select_related("normalized")
    for raw in qs.iterator():
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
