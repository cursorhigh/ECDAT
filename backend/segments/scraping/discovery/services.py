"""Discovery orchestration services (Segment A).

Runs the full pipeline for a ScanJob:
    scanner.run() -> ingest raw -> normalize -> classify -> correlate

Scans are dispatched through the same executor rule as the analysis and
mitigation stages (daemon thread by default, huey when ECDAT_QUEUE_ASYNC=1),
so a running scan can be cancelled at any time and stuck jobs recover on
startup (see sweep_pending_scans).
"""

import logging
import os
import threading
import time

from django.conf import settings
from django.utils import timezone
from huey.contrib.djhuey import db_task
from pydantic import ValidationError

logger = logging.getLogger(__name__)

from core.models import log_action
from .classifier import classify_asset
from .correlation import build_correlations
from .models import CryptoAsset, RawFinding, ScanBatch, ScanJob
from .normalizer import normalize_finding
from .scanners import get_scanner
from .scanners.base import ScanCancelled, ScanContext

# Supported discovery scopes. A scope is how much of a target to cover; the
# scanner decides what a target is.
SCOPE_TYPES = ("quick", "whole", "specified")
# Retained for callers that still use the old name.
SCAN_TYPES = SCOPE_TYPES

# Statuses a job can no longer leave on its own.
_TERMINAL = (
    ScanJob.Status.COMPLETED,
    ScanJob.Status.PARTIAL,
    ScanJob.Status.FAILED,
    ScanJob.Status.CANCELLED,
)

# Human-readable reason for each recorded skip, used in the PARTIAL report.
# Every reason a scanner can emit needs an entry here: an unlabelled reason
# leaks an internal token straight into user-facing text.
_SKIP_LABELS = {
    "file_limit": "an explicit item ceiling was reached",
    "file_too_large": "some items exceeded an explicit size ceiling",
    "unreadable": "some items could not be read",
    "inspect_error": "some items could not be inspected",
    "unrecognised_format": "some files were not in a recognised format",
    "no_certificate_or_key_material": "no certificate or key material was found",
    "not_an_image": "some archives were not container images",
    "not_a_tar_archive": "some archives were not readable as image layers",
    "unreadable_archive": "some image archives could not be read",
    "no_image_manifest": "some archives contained no image manifest",
    "archive_too_large": "some compressed images exceeded the decompression ceiling",
    "no_binary_format": "some files were not a recognised binary format",
    "member_too_large": "some image layer members exceeded the read ceiling",
    "member_limit": "an image contained more members than could be inspected",
    "unsupported_manifest": "some dependency manifests could not be parsed",
    "manifest_unreadable": "some discovered manifests could not be re-read",
}

# Reasons that name an exception class have unbounded cardinality, so they are
# collapsed into a single bounded key rather than growing a new row per class.
_EXCEPTION_REASON_PREFIXES = ("inspect_error:", "yara_error:")


def _bounded_skip_reasons(skipped: dict[str, int]) -> dict[str, int]:
    """Collapse per-exception skip reasons into a single bounded key."""
    out: dict[str, int] = {}
    errors = 0
    for reason, count in (skipped or {}).items():
        if str(reason).startswith(_EXCEPTION_REASON_PREFIXES):
            errors += count
            continue
        out[str(reason)] = out.get(str(reason), 0) + count
    if errors:
        out["inspect_error"] = out.get("inspect_error", 0) + errors
    return out


def _skip_reason_sentence(skipped: dict[str, int]) -> str:
    """One readable sentence describing why coverage was incomplete."""
    if not skipped:
        return "Coverage was incomplete."
    parts = [
        f"{count} {label}"
        for reason, count in sorted(skipped.items(), key=lambda kv: (-kv[1], kv[0]))
        if (label := _SKIP_LABELS.get(reason))
    ]
    if not parts:
        return f"{sum(skipped.values())} items could not be inspected."
    # A count of 1 must still read as English.
    return "; ".join(parts) + "."



def _scan_is_cancelled(scan_job: ScanJob, db: str) -> bool:
    """True once cancellation has been requested for this job.

    A cancel first moves the row to CANCELLING; the worker confirms CANCELLED
    when it observes the request. Both states mean "stop".
    """
    return (
        ScanJob.objects.using(db)
        .filter(
            pk=scan_job.pk,
            status__in=[ScanJob.Status.CANCELLING, ScanJob.Status.CANCELLED],
        )
        .exists()
    )


def record_dependencies(scan_job: ScanJob, db: str) -> int:
    """Persist the dependencies discovered during this scan.

    Reads the manifests the walk already located, so the dependency graph
    reflects the same files the findings came from rather than a second,
    possibly divergent pass over the filesystem. Returns the row count.
    """
    from .models import Dependency
    from .scanners import dependency as dep_parser

    records: list[dict] = []
    unparsable: list[str] = []
    unreadable: list[str] = []
    manifests = (
        RawFinding.objects.using(db)
        .filter(scan_job=scan_job, location__regex=r"(package\.json|requirements.*\.txt|"
                                                 r"pyproject\.toml|Pipfile|setup\.(py|cfg)|"
                                                 r"pom\.xml|build\.gradle|Cargo\.toml|"
                                                 r"go\.mod|Gemfile|composer\.json|"
                                                 r".*\.(csproj|fsproj|vbproj))$")
        .values_list("location", "source_path")
    )

    for location, source_path in manifests:
        filename = os.path.basename(location)
        if not dep_parser.ecosystem_for(filename):
            continue
        # `location` is a display label in quick/whole scope, so it cannot be
        # opened. `source_path` is what the scanner actually read.
        readable = source_path or location
        try:
            with open(readable, "r", encoding="utf-8", errors="replace") as handle:
                text = handle.read()
        except OSError:
            # Previously swallowed silently: the job reported success with an
            # empty dependency graph and no indication anything was missed.
            logger.debug("Could not re-read manifest %s", readable)
            unreadable.append(location)
            continue

        # A malformed manifest must never discard the whole scan. Parse
        # failures are counted and reported, not raised.
        try:
            parsed = dep_parser.parse_manifest(filename, text)
        except Exception:  # noqa: BLE001 - includes RecursionError on deep JSON
            unparsable.append(filename)
            continue

        for dep in parsed:
            info = dep_parser.classify_dependency(dep)
            records.append(
                {
                    "session_id": scan_job.session_id,
                    "scan_job_id": scan_job.pk,
                    "package": dep.package[:256],
                    "version": dep.version[:64],
                    "ecosystem": dep.ecosystem[:32],
                    "scope": dep.scope,
                    "is_crypto": bool(info["is_crypto"]),
                    "relevance": (info.get("relevance") or "")[:32],
                    "capability": (info.get("capability") or "")[:64],
                    "key_service": (info.get("system") or "")[:32],
                    "family": info.get("family") or "unknown",
                    "location": location[:1024],
                    "source_path": readable[:1024],
                    "evidence": {
                        "type": "manifest_entry",
                        "ecosystem": dep.ecosystem,
                        "scope": dep.scope,
                        "line": dep.line,
                        "relevance": info.get("relevance", ""),
                        "capability": info.get("capability", ""),
                    },
                }
            )

    written = 0
    for record in records:
        lookup = {
            "session_id": record["session_id"],
            "package": record["package"],
            "ecosystem": record["ecosystem"],
            "scope": record["scope"],
            "location": record["location"],
        }
        try:
            Dependency.objects.using(db).update_or_create(
                defaults=record, create_defaults=record, **lookup
            )
            written += 1
        except Exception:  # noqa: BLE001
            logger.exception("Could not record dependency %s", record["package"])

    if unparsable:
        logger.warning(
            "Skipped %d unreadable manifest(s): %s", len(unparsable), ", ".join(unparsable[:5])
        )
    scan_job.skip_reasons = _merge_skip_reason(
        scan_job.skip_reasons, "unsupported_manifest", len(unparsable)
    )
    if unreadable:
        # Reported rather than swallowed: a manifest discovery saw but could not
        # re-read means the dependency graph is incomplete, and the job must not
        # imply otherwise.
        logger.warning(
            "Could not re-read %d manifest(s): %s", len(unreadable), ", ".join(unreadable[:5])
        )
    scan_job.skip_reasons = _merge_skip_reason(
        scan_job.skip_reasons, "manifest_unreadable", len(unreadable)
    )
    scan_job.save(using=db, update_fields=["skip_reasons"])
    return written


def _merge_skip_reason(existing, reason: str, count: int):
    """Add to a persisted per-reason skip breakdown, keeping it a dict."""
    if count <= 0:
        return existing or {}
    merged = dict(existing or {})
    merged[reason] = int(merged.get(reason, 0)) + count
    return merged


def _record_lockfile_edges(parsed: dict, path: str, filename: str, session_id, db: str,
                           scan_job_id=None) -> int:
    """Persist a parsed lock file as dependency nodes plus `depends_on` edges.

    A lock file names the packages that are *installed*, but the root project
    that requests them usually appears only as an edge source. That node has to
    exist before the edge can point at anything, so it is created here; without
    it every `depends_on` edge in a standard lock file was silently dropped.
    """
    from .models import Dependency, DependencyRelation

    if not parsed.get("packages") and not parsed.get("edges"):
        return 0

    # Nodes come from the resolved package list, plus any package that only ever
    # appears as an edge endpoint.
    nodes: dict[str, dict] = {}
    for entry in parsed["packages"]:
        name = (entry.get("package") or "")[:256]
        if name:
            nodes[name] = entry
    for parent, _child in parsed.get("edges", []):
        if parent and parent not in nodes:
            # The requesting project: present in the lock file, absent from the
            # flat package list.
            nodes[parent] = {"package": parent, "version": parsed.get("name", ""), "root": True}

    for entry in nodes.values():
        scope = "development" if entry.get("dev") else "runtime"
        # Match on identity, not on path. A package declared in package.json and
        # again in package-lock.json is one dependency, not two; keying on the
        # lock file's own path is what previously produced a duplicate row with
        # `is_crypto` set on one copy and cleared on the other.
        existing = Dependency.objects.using(db).filter(
            session_id=session_id,
            package=entry["package"][:256],
        )
        if session_id is None:
            existing = existing.filter(session_id__isnull=True)
        if scope:
            preferred = existing.filter(scope=scope).order_by("-is_crypto", "id")
        else:
            preferred = existing.order_by("-is_crypto", "id")
        row = preferred.first()
        if row is not None:
            # Already known. The lock file only adds a resolved version and
            # provenance, so enrich rather than duplicate.
            updates = {}
            if entry.get("version") and not row.version:
                updates["version"] = str(entry["version"])[:64]
            evidence = dict(row.evidence or {})
            if evidence.get("type") != "lockfile":
                evidence["resolved_in_lockfile"] = filename
                updates["evidence"] = evidence
            if updates:
                for field, value in updates.items():
                    setattr(row, field, value)
                row.save(using=db, update_fields=list(updates))
            continue
        Dependency.objects.using(db).get_or_create(
            session_id=session_id,
            package=entry["package"][:256],
            ecosystem=(entry.get("ecosystem") or "")[:32],
            scope=scope,
            location=path[:1024],
            defaults={
                "version": (entry.get("version") or "")[:64],
                "is_crypto": False,
                "location": path[:1024],
                "source_path": path[:1024],
                # Attributed to the scan that read the lock file. Without this
                # the package is invisible to any stage that scopes by scan, and
                # the graph silently loses every lock-file-only node.
                "scan_job_id": scan_job_id,
                "evidence": {
                    "type": "lockfile",
                    "source": filename,
                    "flat": bool(parsed.get("flat")),
                    "root_of_graph": bool(entry.get("root")),
                },
            },
        )

    by_name: dict[str, list[Dependency]] = {}
    for name in nodes:
        for candidate in Dependency.objects.using(db).filter(
            session_id=session_id,
            package=name[:256],
        ):
            by_name.setdefault(name, []).append(candidate)

    created = 0
    for parent, child in parsed.get("edges", []):
        for source in by_name.get(parent, []):
            for target in by_name.get(child, []):
                if source.pk == target.pk:
                    continue
                _row, was_created = DependencyRelation.objects.using(db).get_or_create(
                    from_dependency=source,
                    to_dependency=target,
                    relation_type=DependencyRelation.RelationType.DEPENDS_ON,
                    defaults={"session_id": session_id, "detail": filename[:256]},
                )
                created += int(was_created)
    return created


# Asset types a declared crypto library definitively cannot provide.
#
# This is a deny-list rather than an allow-list on purpose. A library supplies
# an algorithm or another library; it does not supply a certificate, a container
# image, a binary, a key, or a cloud account. An asset whose type discovery has
# not pinned down yet is still eligible, because the provisioning evidence is
# carried by the family match and the library being named in the finding, and
# there is no evidence it is one of the artefact kinds above.
_UNPROVIDABLE_ASSET_TYPES = frozenset(
    {
        CryptoAsset.AssetType.CERTIFICATE,
        CryptoAsset.AssetType.BINARY,
        CryptoAsset.AssetType.FIRMWARE,
        CryptoAsset.AssetType.CONTAINER,
        CryptoAsset.AssetType.KEY_REFERENCE,
        CryptoAsset.AssetType.CLOUD_RESOURCE,
        CryptoAsset.AssetType.INFRASTRUCTURE,
        CryptoAsset.AssetType.HARDWARE,
        CryptoAsset.AssetType.NETWORK_ENDPOINT,
        CryptoAsset.AssetType.EXTERNAL_SERVICE,
        CryptoAsset.AssetType.API,
    }
)


def record_dependency_graph(scan_job: ScanJob, db: str) -> int:
    """Build the dependency graph edges for this scan.

    Two edge kinds, from two different sources of truth:

    * ``depends_on`` comes from resolved lock files, so it is the real
      transitive shape ("requests -> cryptography") rather than a guess from
      manifests, which only ever list direct dependencies.
    * ``provides`` links a crypto dependency to the assets discovered under
      the same project, by manifest-directory locality.

    Returns the number of edges created.
    """
    from .models import AssetRelation, CryptoAsset, Dependency, DependencyRelation
    from .scanners import lockfiles
    from .scanners.platform import resolve_scan_roots

    session_id = scan_job.session_id
    created = 0

    # --- resolved lock files -> depends_on edges ---------------------------
    # Lock files do not produce findings, so they have no RawFinding row to be
    # discovered through. They are found where they actually live: beside the
    # manifest that produced the dependencies, walking up a few levels so a
    # monorepo root lock file still reaches a nested package.
    #
    # `source_path` is preferred because `location` is a display label in
    # quick/whole scope; a label like "WORKSPACE" is not a directory that can be
    # walked, which is why the graph used to come back empty outside a targeted
    # scan.
    manifest_dirs: set[str] = set()

    def _dirs(qs):
        found = set()
        for location, source_path in qs.values_list("location", "source_path"):
            candidate = source_path or location
            if candidate and os.path.isabs(candidate):
                found.add(os.path.dirname(candidate))
        return found

    dependencies = Dependency.objects.using(db)
    if session_id is not None:
        dependencies = dependencies.filter(session_id=session_id)
    else:
        # Without a session, matching every unscoped row would pull in
        # dependencies from unrelated scans whose files no longer exist.
        dependencies = dependencies.filter(session_id__isnull=True, scan_job=scan_job)

    # Prefer the directories of this scan's own manifests; widen only if that
    # scan recorded none.
    manifest_dirs = _dirs(dependencies.filter(scan_job=scan_job))
    if not manifest_dirs:
        manifest_dirs = _dirs(dependencies)

    # When no absolute path survived (imported findings, or a scanner that
    # could not record one), fall back to the scan's own roots so the graph is
    # still built from real directories on disk.
    if not manifest_dirs:
        manifest_dirs = {r.root for r in resolve_scan_roots(scan_job) if r.root}

    seen_locks: set[str] = set()
    for manifest_dir in sorted(manifest_dirs, key=len):
        directory = manifest_dir
        for _ in range(4):
            if not directory or directory in seen_locks:
                break
            seen_locks.add(directory)
            for filename in lockfiles.LOCK_FILES:
                candidate = os.path.join(directory, filename)
                if not os.path.isfile(candidate):
                    continue
                try:
                    with open(candidate, "r", encoding="utf-8", errors="replace") as handle:
                        parsed = lockfiles.parse_lockfile(filename, handle.read())
                except OSError:
                    continue
                created += _record_lockfile_edges(
                    parsed, candidate, filename, session_id, db,
                    scan_job_id=scan_job.pk,
                )
            parent = os.path.dirname(directory)
            if parent == directory:
                break
            directory = parent

    # --- crypto dependency -> discovered asset ----------------------------
    crypto_deps = list(
        Dependency.objects.using(db).filter(session_id=session_id, is_crypto=True)
    )
    if crypto_deps:
        assets = list(
            CryptoAsset.objects.using(db)
            .filter(session_id=session_id)
            .values_list(
                "pk", "location", "source_path", "algorithm", "family", "library",
                "asset_type",
            )
        )
        for dependency in crypto_deps:
            # The asset side is keyed by its own real path; comparing a manifest
            # display label against it never matches outside a targeted scan.
            project = os.path.dirname(dependency.source_path or dependency.location or "")
            if not project or not os.path.isabs(project):
                continue
            for asset_row in assets:
                (
                    asset_pk,
                    asset_location,
                    asset_source_path,
                    algorithm,
                    family,
                    library,
                    asset_type,
                ) = asset_row
                asset_real = asset_source_path or asset_location
                if not asset_real:
                    continue
                # Same project: the asset was discovered under the directory
                # whose manifest declared this dependency.
                if not asset_real.startswith(project):
                    continue
                if library and library.split()[0].lower() in dependency.package.lower():
                    detail = "named in the finding"
                elif family and family in (dependency.family or ""):
                    detail = f"same algorithm family ({family})"
                else:
                    # Sharing a directory is co-location, not provisioning.
                    # A `provides` edge asserts this library backs this artefact,
                    # and "it was in the same folder" does not say that. The
                    # graph already carries co-location as its own weaker edge
                    # type, so recording it here would overstate the evidence
                    # and hand the reasoning stage a false claim.
                    continue
                if asset_type in _UNPROVIDABLE_ASSET_TYPES:
                    # A library cannot provide a certificate, a container or a
                    # binary. Those are separate artefacts that happen to sit in
                    # the same project, and linking them here claimed the library
                    # supplies the certificate it merely ships beside.
                    continue
                _created, was_created = DependencyRelation.objects.using(db).get_or_create(
                    from_dependency=dependency,
                    to_asset_id=asset_pk,
                    relation_type=DependencyRelation.RelationType.PROVIDES,
                    defaults={"session_id": session_id, "detail": detail[:256]},
                )
                created += int(was_created)

    return created


def _partial_reason(skipped: dict) -> str:
    return _skip_reason_sentence(_bounded_skip_reasons(skipped))

def run_scan(scan_job: ScanJob) -> ScanJob:
    """Execute a scan job end to end and return it."""
    if scan_job.status in _TERMINAL + (ScanJob.Status.RUNNING,):
        return scan_job

    db = scan_job._state.db or "default"

    # Claim the job with a compare-and-swap so a cancel that lands between
    # creation and pickup is not overwritten back to RUNNING.
    claimed = (
        ScanJob.objects.using(db)
        .filter(pk=scan_job.pk, status=ScanJob.Status.QUEUED)
        .update(
            status=ScanJob.Status.RUNNING,
            progress=0,
            progress_stage="enumerating",
            started_at=timezone.now(),
        )
    )
    if not claimed:
        scan_job.refresh_from_db(using=db)
        return scan_job

    scan_job.status = ScanJob.Status.RUNNING
    scan_job.progress = 0
    scan_job.started_at = timezone.now()

    log_action(
        "scan_created",
        f"Starting {scan_job.source_type} scan on {scan_job.target}",
        "scanjob",
        scan_job.pk,
            )

    def publish(stage: str, scanned: int, total: int | None) -> None:
        # Inspection is 0-80% of the run; persistence and correlation own the
        # rest, so the bar always reflects real work rather than a fixed ladder.
        ratio = (scanned / total) if total else None
        if ratio is None:
            progress = 0
        else:
            progress = min(80, int(ratio * 80))
        ScanJob.objects.using(db).filter(pk=scan_job.pk).update(
            progress=progress,
            progress_stage=stage,
            items_scanned=scanned,
            items_total=total,
        )

    context = ScanContext(on_progress=publish, is_cancelled=lambda: _scan_is_cancelled(scan_job, db))

    try:
        # One job, every selected source.
        #
        # Previously a multi-source request created one ScanJob per source, which
        # made a single user action look like several scans and gave it several
        # independent status lines. The sources share a session either way, so
        # correlation and the dependency graph already saw them as one body of
        # work -- splitting them across jobs only split the presentation. Now the
        # job runs each source's scanner in turn and persists everything into
        # itself, which is what the user meant by "one scan".
        #
        # `plan_sources` decides which sources suit the chosen target, so a
        # folder target does not fail outright because certificates were also
        # selected; those are recorded as skipped instead.
        requested_sources = [
            s
            for s in (list(scan_job.config.get("source_types") or []) or [scan_job.source_type])
            if s
        ]
        scan_kind = "folder" if (scan_job.config.get("scan_type") in ("quick", "whole")) else target_kind(scan_job.target)
        runnable, excluded = [], []
        for source in requested_sources:
            from .scanners import PLANNED_SOURCES, SCANNER_REGISTRY

            if source not in SCANNER_REGISTRY:
                label = PLANNED_SOURCES.get(source, {}).get("name", source)
                excluded.append({"source": source, "reason": f"{label} is not implemented."})
                continue
            supported = SCANNER_REGISTRY[source].supported_targets
            if supported and scan_kind not in supported:
                excluded.append(
                    {
                        "source": source,
                        "reason": f"Needs a {' or '.join(supported)} target; this target is a {scan_kind}.",
                    }
                )
                continue
            runnable.append(source)

        if not runnable:
            detail = " ".join(f"{item['source']}: {item['reason']}" for item in excluded)
            raise ScanInspectionError(f"No selected source can run against this target. {detail}")

        total_sources = len(runnable)
        ingested = 0
        scanned_total = 0
        total_items = 0
        any_measured = False

        for index, source in enumerate(runnable, start=1):
            if _scan_is_cancelled(scan_job, db):
                raise ScanCancelled(scan_job.pk)

            def publish_source(stage, scanned, total, _i=index):
                # Inspection is 0-80% of the run, split evenly across the
                # sources, so the bar still reflects real work as each one
                # finishes rather than restarting at 0% for the next.
                share = 80.0 / total_sources
                ratio = (scanned / total) if total else None
                progress = min(80, int((_i - 1) * share + (share if ratio is None else ratio * share)))
                ScanJob.objects.using(db).filter(pk=scan_job.pk).update(
                    progress=progress,
                    progress_stage=f"{source}:{stage}",
                    items_scanned=scanned_total + scanned,
                    items_total=(total_items + total) if total is not None else None,
                )

            source_context = ScanContext(
                on_progress=publish_source,
                is_cancelled=lambda: _scan_is_cancelled(scan_job, db),
            )
            scanner = get_scanner(scan_job, source)
            raw_findings = scanner.run(source_context)

            # Carry the scanner's measured coverage forward; deriving it from a
            # finding count would report a meaningless "files inspected" figure.
            measured = source_context.scanned if source_context.scanned is not None else len(raw_findings)
            if source_context.scanned is not None:
                any_measured = True
            source_context.report(
                "persisting",
                measured,
                source_context.total,
            )
            if source_context.scanned is not None:
                scanned_total += source_context.scanned
            if source_context.total is not None:
                total_items += source_context.total

            ingested += scanner.ingest(raw_findings)
            for reason, count in (getattr(source_context, "skipped", {}) or {}).items():
                context.record_skip(reason, count)
            ScanJob.objects.using(db).filter(pk=scan_job.pk).update(
                progress=min(80, int(index * (80.0 / total_sources))),
                progress_stage=f"{source}:persisted",
            )

        if excluded:
            for item in excluded:
                log_action(
                    "scan_source_excluded",
                    f"{item['source']} not run: {item['reason']}",
                    "scanjob",
                    scan_job.pk,
                )

        # Publish the run's aggregate coverage on the job-level context.
        #
        # Each source reports through its own ScanContext now, so without this the
        # job's measured totals stayed unset and the persisting stage below
        # reported a figure derived from a finding count instead -- which is
        # exactly the "files inspected" number the coverage contract forbids.
        context.scanned = scanned_total if any_measured else None
        context.total = total_items if any_measured else None
        context.stage = "persisted"
        ScanJob.objects.using(db).filter(pk=scan_job.pk).update(
            progress=min(80, int(len(runnable) * (80.0 / total_sources))),
            progress_stage="persisted",
            items_scanned=scanned_total,
            items_total=total_items if any_measured else None,
        )


        # Normalize + classify each raw finding (all inside the same DB).
        # Cancellation is honoured between findings so a user's cancel lands
        # promptly even on a huge scan.
        ScanJob.objects.using(db).filter(pk=scan_job.pk).update(
            progress=85, progress_stage="normalizing"
        )
        qs = RawFinding.objects.using(db).filter(scan_job=scan_job).select_related("normalized")
        for index, raw in enumerate(qs.iterator(), start=1):
            if _scan_is_cancelled(scan_job, db):
                raise ScanCancelled(scan_job.pk)
            norm = normalize_finding(raw, using=db, session_id=scan_job.session_id)
            classify_asset(norm, using=db, session_id=scan_job.session_id)
            if index % 200 == 0:
                ScanJob.objects.using(db).filter(pk=scan_job.pk).update(
                    progress=85 + min(10, int(index / max(1, ingested) * 10)),
                    progress_stage="normalizing",
                )

        ScanJob.objects.using(db).filter(pk=scan_job.pk).update(
            progress=95, progress_stage="correlating"
        )
        build_correlations(
            using=db,
            assets=CryptoAsset.objects.using(db).filter(session_id=scan_job.session_id),
        )

        # Dependency graph: recorded after classification so the crypto
        # dependencies can be related to the assets that use them.
        ScanJob.objects.using(db).filter(pk=scan_job.pk).update(
            progress=97, progress_stage="resolving_dependencies"
        )
        record_dependencies(scan_job, db)
        record_dependency_graph(scan_job, db)

        # Refresh the unified relationship graph so the two previously
        # disconnected graphs (assets, dependencies) become one. Failure here
        # must not lose the scan: the index is derived and can be rebuilt.
        try:
            from .graph_index import build_graph_index

            build_graph_index(db, session_id=scan_job.session_id, scan_job=scan_job)
        except Exception:  # noqa: BLE001
            logger.exception("Could not refresh the relationship graph index")

        # A cancel that lands after the last work item must beat COMPLETED.
        if _scan_is_cancelled(scan_job, db):
            raise ScanCancelled(scan_job.pk)

        skipped = _bounded_skip_reasons(getattr(context, "skipped", {}) or {})
        partial = bool(skipped)
        now = timezone.now()

        ScanJob.objects.using(db).filter(pk=scan_job.pk).update(
            status=ScanJob.Status.PARTIAL if partial else ScanJob.Status.COMPLETED,
            progress=100,
            progress_stage="done",
            items_skipped=sum(skipped.values()),
            skip_reasons=skipped,
            error=_skip_reason_sentence(skipped) if partial else "",
            error_code="PARTIAL_COVERAGE" if partial else "",
            error_scope="discovery" if partial else "",
            error_recoverable=True if partial else None,
            error_action=(
                "Re-run without an explicit ceiling, or inspect the skipped locations."
                if partial
                else ""
            ),
            finished_at=now,
        )
        scan_job.refresh_from_db(using=db)

        log_action(
            "scan_completed",
            f"Scan {scan_job.source_type} {'partial' if partial else 'complete'}: "
            f"{ingested} raw findings",
            "scanjob",
            scan_job.pk,
                    )
        log_action(
            "findings_ingested",
            f"Ingested {ingested} raw findings",
            "scanjob",
            scan_job.pk,
                    )

        # Normalization, classification, correlation and the dependency graph
        # have already run above. Re-running them here would duplicate every
        # asset occurrence and overwrite the PARTIAL status decided just above,
        # so only the follow-on analysis is triggered.
        _auto_analyze(scan_job)
    except ScanCancelled:
        # Keep the real progress reached; do not rewind to 0.
        ScanJob.objects.using(db).filter(pk=scan_job.pk).update(
            status=ScanJob.Status.CANCELLED,
            progress_stage="cancelled",
            error="Cancelled by user",
            error_code="CANCELLED",
            error_scope="discovery",
            error_recoverable=True,
            error_action="Start a new discovery scan to cover the target again.",
            finished_at=timezone.now(),
        )
        scan_job.refresh_from_db(using=db)
        _refresh_parent_batch(scan_job, db)
        log_action("scan_cancelled", f"Scan {scan_job.source_type} cancelled",
                   "scanjob", scan_job.pk)
    except Exception as exc:  # noqa: BLE001
        ScanJob.objects.using(db).filter(pk=scan_job.pk).update(
            status=ScanJob.Status.FAILED,
            progress_stage="failed",
            error=str(exc),
            error_code=type(exc).__name__[:48],
            error_scope="discovery",
            error_recoverable=False,
            error_action="Review the reported reason and re-run the discovery scan.",
            finished_at=timezone.now(),
        )
        scan_job.refresh_from_db(using=db)
        _refresh_parent_batch(scan_job, db)
        log_action("system", f"Scan failed: {exc}", "scanjob", scan_job.pk)

    return scan_job


# ---------------------------------------------------------------------------
# Dispatch + cancellation (mirrors analysis/mitigation execution rules)
# ---------------------------------------------------------------------------


def _dispatch_scan(scan_job: ScanJob, db: str) -> ScanJob:
    """Run a queued scan through the configured executor.

    Daemon thread by default (plain runserver); ECDAT_QUEUE_ASYNC=1 routes
    through huey for the dedicated worker. Returns the job unchanged.
    """
    from core.modes import active_mode

    mode = active_mode()
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


def _is_transient_db_error(exc: BaseException) -> bool:
    """True for errors that mean "try again", not "this will never work".

    SQLite is single-writer, so a multi-source run can lose a write race. That
    is contention, not a broken scan, and must never be reported as a failure.
    """
    text = str(exc).lower()
    return "database is locked" in text or "database table is locked" in text


def run_scan_by_pk(scan_job_id: int, mode: str) -> ScanJob | None:
    """Load a scan job from its mode DB and run the full pipeline.

    Retries a lock-contention failure rather than failing the job: another
    source in the same batch may simply have been mid-write.
    """
    from core.modes import active_mode, db_alias_for_mode

    db = db_alias_for_mode(mode)
    job = ScanJob.objects.using(db).filter(pk=scan_job_id).first()
    if job is None:
        return None

    # Sources in one batch run concurrently and all write to the same database.
    # Serialize them per batch so they queue behind each other instead of
    # colliding, and retry once anyway in case another writer got there first.
    with _batch_lock(job):
        for attempt in range(3):
            try:
                return run_scan(job)
            except Exception as exc:  # noqa: BLE001
                if not _is_transient_db_error(exc) or attempt == 2:
                    raise
                logger.warning(
                    "Scan %s hit write contention (attempt %s/3): %s",
                    scan_job_id, attempt + 1, exc,
                )
                time.sleep(0.5 * (attempt + 1))
    return None


# One lock per batch, so sources of the same run never write at the same time.
_BATCH_LOCKS: dict[str, threading.Lock] = {}
_BATCH_LOCKS_GUARD = threading.Lock()


def _batch_lock(job: ScanJob) -> threading.Lock:
    key = f"{job._state.db or 'default'}:{job.batch_id or job.pk}"
    with _BATCH_LOCKS_GUARD:
        lock = _BATCH_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _BATCH_LOCKS[key] = lock
        return lock


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
            "run_scan_task: scan %s crashed: %s", scan_job_id, exc
        )


def cancel_scan_job(scan_job: ScanJob) -> bool:
    """Request cancellation of a scan job; return True if the request was accepted.

    A cancel moves the row to CANCELLING, not straight to CANCELLED: the worker
    may still be mid-walk, and only the worker knows when it has actually
    stopped. Reporting "cancelled" immediately is what previously let a scan
    keep writing findings after the user was told it had stopped.
    """
    db = scan_job._state.db or "default"
    won = (
        ScanJob.objects.using(db)
        .filter(
            pk=scan_job.pk,
            status__in=[ScanJob.Status.QUEUED, ScanJob.Status.RUNNING],
        )
        .update(
            status=ScanJob.Status.CANCELLING,
            progress_stage="cancelling",
            error="Cancellation requested",
            error_code="CANCELLING",
            error_scope="discovery",
            error_recoverable=True,
            error_action="Waiting for the scan worker to stop.",
        )
    )
    if not won:
        return False

    # A queued job has no worker to notice, so finish the cancellation here.
    if scan_job.status == ScanJob.Status.QUEUED:
        ScanJob.objects.using(db).filter(pk=scan_job.pk).update(
            status=ScanJob.Status.CANCELLED,
            progress_stage="cancelled",
            error="Cancelled by user",
            error_code="CANCELLED",
            error_recoverable=True,
            error_action="Start a new discovery scan to cover the target again.",
            finished_at=timezone.now(),
        )

    scan_job.refresh_from_db(using=db)
    log_action("scan_cancelled", f"Cancellation requested for {scan_job.source_type} scan",
               "scanjob", scan_job.pk)
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

        # A job left mid-cancellation by a dead worker can never be stopped by
        # anyone now, so resolve it rather than re-queueing work the user asked
        # to abandon.
        ScanJob.objects.using(db).filter(status=ScanJob.Status.CANCELLING).update(
            status=ScanJob.Status.CANCELLED,
            progress_stage="cancelled",
            error="Cancelled by user",
            error_code="CANCELLED",
            error_recoverable=True,
            finished_at=timezone.now(),
        )

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
               "scanjob", job.pk)
    # Enqueue on the persistent huey queue (like the analysis/plan sweeps) so
    # the worker survives; `_dispatch_scan`'s thread branch would be killed
    # when this CLI command exits and the scan would stay queued forever.
    run_scan_task(job.pk, active_mode())


class ScanInspectionError(ValueError):
    """Raised when the user-supplied scan parameters are invalid."""


def create_and_run_scan(source_type: str, target: str = "", config: dict | None = None,
                        scan_type: str = "specified", session_id: int | None = None,
                        source_types: list[str] | None = None) -> ScanJob:
    """Create and run a scan with user-supplied parameters.

    `scan_type` selects the scope of the run:
      - "quick"     -> fast scan of the current working directory
      - "whole"     -> scan the entire system
      - "specified" -> scan the folder given in `target`

    The ScanJob is created in the single database. `session_id`
    scopes the whole scan (job, findings, assets) to a work session.
    """
    from core import modes as modes_mod

    source_type = (source_type or "").strip()
    target = (target or "").strip()
    scan_type = (scan_type or "specified").strip()

    if source_type not in ScanJob.SourceType.values:
        raise ScanInspectionError(f"Unknown source type '{source_type}'.")

    # Reject sources that have no implementation now, rather than accepting the
    # job and failing it asynchronously with a "no scanner registered" error.
    from .scanners import PLANNED_SOURCES, SCANNER_REGISTRY

    scanner_cls = SCANNER_REGISTRY.get(source_type)
    if scanner_cls is None:
        label = PLANNED_SOURCES.get(source_type, {}).get("name", source_type)
        raise ScanInspectionError(
            f"Discovery source '{label}' is not available in this deployment."
        )

    if scan_type not in SCOPE_TYPES:
        raise ScanInspectionError(f"Unknown discovery scope '{scan_type}'.")

    if scan_type == "quick":
        target = target or "quick"
    elif scan_type == "whole":
        target = target or "whole"
    elif not target:
        raise ScanInspectionError("Choose a target to discover.")

    # Let the scanner own target + configuration rules (Validate Target step).
    try:
        target = scanner_cls.validate_target(target, config)
        config = scanner_cls.validate_config(config)
    except ValueError as exc:
        raise ScanInspectionError(str(exc)) from None

    db = modes_mod.active_db()

    scan_config = dict(config or {})
    scan_config["scan_type"] = scan_type
    # The full set of sources this job covers. `source_type` only records the
    # primary one, so the list has to live on the job for run_scan to iterate.
    if source_types:
        scan_config["source_types"] = [s for s in source_types if s]
    job = ScanJob.objects.using(db).create(
        source_type=source_type,
        target=target,
                config=scan_config,
        status=ScanJob.Status.QUEUED,
        session_id=session_id,
    )
    log_action("scan_created", f"Queued {source_type} scan on {target}", "scanjob", job.pk)
    return _dispatch_scan(job, db)


# --- multi-source discovery ------------------------------------------------

# A target that is a single file can only be read by sources that accept one.
# This is used to exclude sources automatically rather than failing a run the
# user never asked to be limited.
def target_kind(target: str) -> str:
    """Classify a target as 'file', 'folder', or 'unknown'."""
    from pathlib import Path

    raw = (target or "").strip().strip('"')
    if not raw or raw.lower() in ("quick", "whole"):
        return "folder"
    try:
        return "file" if Path(raw).is_file() else "folder"
    except OSError:
        return "unknown"


def plan_sources(source_types: list[str], target: str, scan_type: str) -> tuple[list[str], list[dict]]:
    """Decide which sources can actually run, and why the rest cannot.

    Returns (runnable, excluded). Selecting every available source is the
    default, so this is what keeps "just discover everything" from failing on
    the first source that does not suit the chosen target.
    """
    from .scanners import PLANNED_SOURCES, SCANNER_REGISTRY

    runnable: list[str] = []
    excluded: list[dict] = []
    kind = "folder" if scan_type in ("quick", "whole") else target_kind(target)

    for source in source_types:
        if source not in SCANNER_REGISTRY:
            label = PLANNED_SOURCES.get(source, {}).get("name", source)
            excluded.append({"source": source, "reason": f"{label} is not implemented."})
            continue
        supported = SCANNER_REGISTRY[source].supported_targets
        if supported and kind not in supported:
            needed = " or ".join(supported)
            excluded.append(
                {
                    "source": source,
                    "reason": f"Needs a {needed} target; this target is a {kind}.",
                }
            )
            continue
        runnable.append(source)
    return runnable, excluded


def create_batch_scan(source_types: list[str] | None = None, target: str = "",
                     scan_type: str = "specified",
                     session_id: int | None = None) -> ScanBatch:
    """Run one discovery pass across several sources.

    Each source becomes its own ScanJob so per-source progress, cancellation
    and partial-coverage reporting keep working unchanged. The returned batch
    is the single handle the UI needs.
    """
    from core import modes as modes_mod
    from .models import ScanBatch

    db = modes_mod.active_db()

    requested = [s for s in (source_types or []) if s in ScanJob.SourceType.values]
    if not requested:
        raise ScanInspectionError("Choose at least one discovery source.")
    if len(set(requested)) != len(requested):
        raise ScanInspectionError("The same discovery source was selected twice.")

    scan_type = (scan_type or "specified").strip()
    if scan_type not in SCOPE_TYPES:
        raise ScanInspectionError(f"Unknown discovery scope '{scan_type}'.")
    if scan_type == "specified" and not (target or "").strip():
        raise ScanInspectionError("Choose a target to discover.")

    runnable, excluded = plan_sources(requested, target, scan_type)
    if not runnable:
        detail = " ".join(f"{item['source']}: {item['reason']}" for item in excluded)
        raise ScanInspectionError(f"No selected source can run against this target. {detail}")

    batch = ScanBatch.objects.using(db).create(
        target=target,
        scan_type=scan_type,
        source_types=requested,
        excluded=excluded,
        status=ScanJob.Status.QUEUED,
                session_id=session_id,
    )

    # One source failing to start must not abandon the others, so each is
    # created independently and any failure is recorded against the batch.
    for source in runnable:
        try:
            job = create_and_run_scan(
                source_type=source,
                target=target,
                scan_type=scan_type,
                                session_id=session_id,
            )
        except ScanInspectionError as exc:
            excluded.append({"source": source, "reason": str(exc)})
            batch.excluded = excluded
            batch.save(using=db, update_fields=["excluded"])
            continue
        ScanJob.objects.using(db).filter(pk=job.pk).update(batch_id=batch.pk)

    refresh_batch_status(batch, db)
    log_action(
        "scan_batch_created",
        f"Queued discovery across {len(runnable)} source(s) on {target}",
        "scanbatch",
        batch.pk,
            )
    return batch


def _refresh_parent_batch(scan_job, db: str) -> None:
    """Keep a multi-source parent in step when one of its jobs settles."""
    batch_id = getattr(scan_job, "batch_id", None)
    if not batch_id:
        return
    batch = ScanBatch.objects.using(db).filter(pk=batch_id).first()
    if batch is not None:
        refresh_batch_status(batch, db)


def refresh_batch_status(batch, db: str):
    """Recompute a batch's status and progress from its jobs.

    Derived, never set independently, so the summary can never claim more
    coverage than the individual scans actually achieved.
    """
    from .models import ScanBatch

    jobs = list(
        ScanJob.objects.using(db)
        .filter(batch=batch)
        .values_list("status", "progress")
    )
    if not jobs:
        return batch

    statuses = [status for status, _ in jobs]
    active = {"queued", "validating", "running"}

    if any(status == ScanJob.Status.CANCELLING for status in statuses):
        status = ScanJob.Status.CANCELLING
    elif any(status in active for status in statuses):
        status = ScanJob.Status.RUNNING
    else:
        succeeded = {
            ScanJob.Status.COMPLETED,
            ScanJob.Status.PARTIAL,
        }
        if all(s == ScanJob.Status.CANCELLED for s in statuses):
            status = ScanJob.Status.CANCELLED
        elif all(s == ScanJob.Status.COMPLETED for s in statuses):
            status = ScanJob.Status.COMPLETED
        elif any(s in succeeded for s in statuses):
            # Something was read even though not everything finished cleanly.
            status = ScanJob.Status.PARTIAL
        else:
            status = ScanJob.Status.FAILED

    finished = status not in active and status != ScanJob.Status.CANCELLING
    progress = 100 if finished else round(sum(p for _, p in jobs) / len(jobs))

    updates = {"status": status, "progress": progress}
    if finished and not batch.finished_at:
        updates["finished_at"] = timezone.now()
    if not finished and not batch.started_at:
        updates["started_at"] = timezone.now()
    ScanBatch.objects.using(db).filter(pk=batch.pk).update(**updates)
    batch.status = status
    batch.progress = progress
    return batch


def cancel_batch(batch, db: str) -> int:
    """Request cancellation of every job in a batch. Returns jobs affected."""
    from .models import ScanBatch

    jobs = list(ScanJob.objects.using(db).filter(batch=batch).exclude(
        status__in=_TERMINAL
    ))
    for job in jobs:
        cancel_scan_job(job)
    ScanBatch.objects.using(db).filter(pk=batch.pk).update(
        status=ScanJob.Status.CANCELLING
    )
    batch.status = ScanJob.Status.CANCELLING
    return len(jobs)


def validate_import_payload(payload: dict) -> tuple[str, str, list[dict]]:
    """Validate an import body against the shared handoff contract.

    Returns (source_type, target, findings) with every finding normalised to a
    dict. Raises ScanInspectionError with a caller-fixable message when the
    payload does not match, so a bad export is rejected before anything is
    written rather than failing part-way through the pipeline.
    """
    from schema.contracts.raw_finding import ScanIngestPayload

    if not isinstance(payload, dict):
        raise ScanInspectionError("The import body must be a JSON object.")

    raw_findings = payload.get("findings")
    if not isinstance(raw_findings, list):
        raise ScanInspectionError("`findings` must be a list of raw finding objects.")

    try:
        contract = ScanIngestPayload.model_validate(
            {
                "source_type": payload.get("source_type") or ScanJob.SourceType.SOURCE_CODE,
                "target": payload.get("target") or "",
                "findings": raw_findings,
            }
        )
    except ValidationError as exc:
        raise ScanInspectionError(_describe_validation_error(exc)) from None

    findings = [item.model_dump() for item in contract.findings]
    return contract.source_type, contract.target, findings


def _describe_validation_error(exc: ValidationError) -> str:
    """Turn a pydantic error into one actionable sentence."""
    parts = []
    for error in exc.errors()[:5]:
        location = ".".join(str(piece) for piece in error["loc"]) or "payload"
        parts.append(f"{location}: {error['msg']}")
    remaining = exc.errors().__len__() - 5
    if remaining > 0:
        parts.append(f"(+{remaining} more)")
    return "The findings payload is invalid -> " + "; ".join(parts)


def ingest_external_findings(source_type: str, findings: list[dict], target: str = "",
                             mode: str | None = None,
                             session_id: int | None = None) -> ScanJob:
    """Create a ScanJob and ingest raw findings supplied directly as JSON data.

    This is the "accept calls with data to scan" entry point: a scanner can
    push already-extracted artefact findings (rather than have ECDAT walk a
    local folder). Each `findings` element is validated against the shared
    handoff contract before anything is persisted. The normalizer/classifier/
    correlator then run exactly as they would for a folder scan. `session_id`
    scopes the ingest (job + findings + assets) to a work session.
    """
    from core import modes as modes_mod

    source_type = (source_type or "").strip() or ScanJob.SourceType.SOURCE_CODE

    if source_type not in ScanJob.SourceType.values:
        raise ScanInspectionError(f"Unknown source type '{source_type}'.")

    # Match the scanner-ingest path: a source the product advertises as
    # unimplemented must not be creatable here as a bare label. Findings
    # supplied by a caller are still recorded, but under a source that exists.
    from .scanners import SCANNER_REGISTRY

    if source_type not in SCANNER_REGISTRY:
        raise ScanInspectionError(
            f"Findings cannot be imported for '{source_type}' because that "
            "discovery source is not implemented."
        )

    if not isinstance(findings, list):
        raise ScanInspectionError("`findings` must be a list of raw finding objects.")

    db = modes_mod.active_db()
    job = ScanJob.objects.using(db).create(
        source_type=source_type,
        target=(target or "").strip() or "external-data",
                config={"external": True},
        status=ScanJob.Status.QUEUED,
        session_id=session_id,
    )
    log_action("scan_created", f"Ingesting {len(findings)} external findings ({source_type})",
               "scanjob", job.pk)

    # Persist the raw findings (same behaviour as a scanner's ingest()).
    job.status = ScanJob.Status.RUNNING
    job.progress = 0
    job.progress_stage = "persisting"
    job.items_total = len(findings)
    job.started_at = timezone.now()
    job.save(using=db, update_fields=["status", "progress", "progress_stage", "items_total", "started_at"])

    count = 0
    for item in findings:
        if _scan_is_cancelled(job, db):
            ScanJob.objects.using(db).filter(pk=job.pk).update(
                status=ScanJob.Status.CANCELLED,
                progress_stage="cancelled",
                error="Cancelled by user",
                error_code="CANCELLED",
                error_recoverable=True,
                finished_at=timezone.now(),
            )
            job.refresh_from_db(using=db)
            log_action("scan_cancelled", f"External ingest ({source_type}) cancelled",
                       "scanjob", job.pk)
            return job
        RawFinding.objects.using(db).create(
            scan_job=job,
                        source_type=source_type,
            location=item.get("location", ""),
            raw_json=item,
            session_id=session_id,
        )
        count += 1
        if count % 200 == 0:
            ScanJob.objects.using(db).filter(pk=job.pk).update(
                progress=min(80, int(count / max(1, len(findings)) * 80)),
                items_scanned=count,
            )
    job.findings_count = count
    job.items_scanned = count
    job.save(using=db, update_fields=["findings_count", "items_scanned"])

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
                       "scanjob", scan_job.pk)
            return
        norm = normalize_finding(raw, using=db, session_id=session_id)
        classify_asset(norm, using=db, session_id=session_id)

    build_correlations(
        using=db,
        assets=CryptoAsset.objects.using(db).filter(session_id=session_id),
    )

    scan_job.refresh_from_db(using=db, fields=["status", "progress", "items_skipped"])
    # Never overwrite an honest terminal state. A job that reported PARTIAL
    # coverage must stay PARTIAL, and a cancelled job must stay cancelled.
    if scan_job.status in (ScanJob.Status.PARTIAL, ScanJob.Status.CANCELLED):
        return

    scan_job.status = ScanJob.Status.COMPLETED
    scan_job.progress = 100
    scan_job.finished_at = timezone.now()
    scan_job.save(using=db, update_fields=["status", "progress", "finished_at"])
    log_action("scan_completed",
               f"Scan {source_type} complete: {scan_job.findings_count} raw findings",
               "scanjob", scan_job.pk)

    _auto_analyze(scan_job)


def _auto_analyze(scan_job) -> None:
    """Once processing is done, stage analysis for a context choice (opt-out via env).

    The run is created awaiting the user's context choice (default context
    auto-continues after the configurable timeout) - opt out by setting
    ECDAT_AUTO_ANALYSE=0.

    Staging is deliberately allowed to fail. By the time this is called the scan
    has already ingested, normalised, classified and correlated its findings, and
    written its real terminal status. If `pending_analysis` raises -- a schema the
    running process has not caught up with, a transient database error -- letting
    that escape would land in `run_scan`'s generic handler and relabel a scan that
    had in fact finished as FAILED, throwing away hundreds of collected findings
    over a follow-on step. That is how job #70 lost 333 findings.

    A failure here is recorded and the scan keeps the result it earned; the
    operator can start the analysis by hand from the scans page.
    """
    try:
        _stage_auto_analysis(scan_job)
    except Exception as exc:  # noqa: BLE001
        log_action(
            "system",
            f"Analysis could not be staged for scan {scan_job.pk}: {exc}. "
            "The scan itself completed; start the analysis manually.",
            "scanjob",
            scan_job.pk,
        )


def _stage_auto_analysis(scan_job) -> None:
    """Create the awaiting-context run for a finished scan."""
    import os

    if os.environ.get("ECDAT_AUTO_ANALYSE", "1") == "0":
        return

    from segments.scraping.discovery.models import NormalizedFinding

    db = scan_job._state.db or "default"
    if scan_job.findings_count <= 0 and not (
        NormalizedFinding.objects.using(db).filter(raw_finding__scan_job=scan_job).exists()
    ):
        return

    from segments.ml.analysis.models import AnalysisRun

    if AnalysisRun.objects.using(db).filter(
        scan_job=scan_job,
        status__in=[
            AnalysisRun.Status.AWAITING_CONTEXT,
            AnalysisRun.Status.QUEUED,
            AnalysisRun.Status.RUNNING,
        ],
    ).exists():
        return

    from segments.ml.analysis.runner import pending_analysis

    pending_analysis(scan_job)
