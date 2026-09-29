"""Scanner adapters for Segment A (Discovery).

Each scanner subclass knows how to inspect one source type and emit
RawFindings. For this phase scanners run synchronously; long-running
scanners can be moved to Celery later without changing their interface.
"""

from abc import ABC, abstractmethod

from pydantic import ValidationError

from ..models import RawFinding, ScanJob


class ScanCancelled(Exception):
    """Raised inside a scanner when the job was cancelled mid-flight."""


class ScanContext:
    """Channel between a scanner and the orchestrator.

    Scanners report measured progress, record what they could not inspect, and
    poll for cancellation through this object. Progress is always derived from
    real work (items inspected / items discovered) rather than a fixed ladder.
    """

    def __init__(self, on_progress=None, is_cancelled=None, on_skip=None):
        self._on_progress = on_progress
        self._is_cancelled = is_cancelled
        self._on_skip = on_skip
        self.skipped: dict[str, int] = {}
        # The most recent measured coverage the scanner published, kept so the
        # orchestrator can report the real inspected/total pair instead of
        # re-deriving it from a finding count.
        self.scanned: int | None = None
        self.total: int | None = None
        self.stage: str = ""

    def report(self, stage: str, scanned: int, total: int | None) -> None:
        """Publish measured progress. `total=None` means 'not yet known'."""
        if total is not None:
            self.stage = stage
            self.scanned = scanned
            self.total = total
        if self._on_progress:
            self._on_progress(stage=stage, scanned=scanned, total=total)

    def check_cancelled(self) -> None:
        """Raise ScanCancelled if the job was cancelled. Cheap enough to poll."""
        if self._is_cancelled and self._is_cancelled():
            raise ScanCancelled()

    def record_skip(self, reason: str, count: int = 1) -> None:
        """Record that `count` items could not be inspected, and why."""
        self.skipped[reason] = self.skipped.get(reason, 0) + count
        if self._on_skip:
            self._on_skip(reason, count)


class BaseScanner(ABC):
    """Interface all scanners implement.

    Subclasses also declare registry metadata (id, name, version, supported
    targets/artifacts, capabilities, configuration schema) so the API can
    describe what discovery can actually do instead of the UI hard-coding it.
    """

    # --- registry metadata -------------------------------------------------
    scanner_id = ""
    name = ""
    description = ""
    version = "1.0.0"
    supported_targets: tuple[str, ...] = ()
    supported_artifacts: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    # Field descriptors the UI renders: key -> {type, label, default, min}
    configuration_schema: dict[str, dict] = {}
    status = "planned"

    source_type = ScanJob.SourceType.SOURCE_CODE

    def __init__(self, scan_job: ScanJob):
        self.scan_job = scan_job

    @abstractmethod
    def run(self, context: ScanContext | None = None) -> list[dict]:
        """Return a list of raw finding dicts for this target.

        Implementations should poll `context.check_cancelled()` during long
        work, call `context.report(...)` with measured counts, and record
        anything they could not inspect via `context.record_skip(...)`.
        """

    @classmethod
    def describe(cls) -> dict:
        """Return this scanner's registry metadata as a JSON-safe dict."""
        return {
            "id": cls.scanner_id or cls.source_type,
            "source_type": cls.source_type,
            "name": cls.name or cls.source_type,
            "description": cls.description,
            "version": cls.version,
            "supported_targets": list(cls.supported_targets),
            "supported_artifacts": list(cls.supported_artifacts),
            "capabilities": list(cls.capabilities),
            "configuration_schema": dict(cls.configuration_schema),
            "status": cls.status,
        }

    @classmethod
    def validate_target(cls, target: str, config: dict | None = None) -> str:
        """Validate a target before discovery starts and return the resolved one.

        This is the `Validate Target` step of the discovery lifecycle. The
        default accepts any non-empty target; scanners that address something
        other than a path (an image ref, a repository, an account) override it
        so their rules live with the scanner instead of the orchestrator.
        """
        target = (target or "").strip()
        if not target:
            raise ValueError("Choose a target to discover.")
        return target

    @classmethod
    def validate_config(cls, config: dict | None = None) -> dict:
        """Validate supplied configuration against `configuration_schema`.

        Unknown keys are rejected so a typo cannot silently do nothing.
        """
        config = dict(config or {})
        schema = cls.configuration_schema or {}
        if not schema:
            if config:
                raise ValueError(
                    f"{cls.name} accepts no configuration options "
                    f"(received: {', '.join(sorted(config))})."
                )
            return config

        unknown = sorted(set(config) - set(schema))
        if unknown:
            raise ValueError(
                f"Unknown option(s) for {cls.name}: {', '.join(unknown)}. "
                f"Supported: {', '.join(sorted(schema))}."
            )
        for key, value in config.items():
            field = schema[key]
            if field.get("type") == "integer" and not isinstance(value, int):
                raise ValueError(f"Option '{key}' must be a whole number.")
        return config

    def ingest(self, findings: list[dict]) -> int:
        """Validate and persist raw findings against the scan job.

        Every scanner's output passes the shared handoff contract here, so
        scanners cannot diverge in the shape they emit.
        """
        from schema.contracts.raw_finding import ScanIngestPayload

        db = self.scan_job._state.db or "default"
        try:
            contract = ScanIngestPayload(
                source_type=self.source_type,
                target=self.scan_job.target,
                findings=findings,
            )
        except ValidationError as exc:
            raise ValueError(
                f"{self.name} produced an invalid finding: {_first_contract_error(exc)}"
            ) from None

        count = 0
        for item in contract.findings:
            payload = item.model_dump()
            RawFinding.objects.using(db).create(
                scan_job=self.scan_job,
                source_type=self.source_type,
                location=payload.get("location", ""),
                # Kept separate from the display label so later stages can
                # re-read the artefact without guessing at a path.
                source_path=payload.get("source_path", ""),
                raw_json=payload,
                session_id=self.scan_job.session_id,
            )
            count += 1
        self.scan_job.findings_count = count
        self.scan_job.save(using=db, update_fields=["findings_count"])
        return count


def _first_contract_error(exc: ValidationError) -> str:
    errors = exc.errors()
    if not errors:
        return "payload did not match the finding contract."
    first = errors[0]
    location = ".".join(str(piece) for piece in first["loc"]) or "finding"
    return f"{location}: {first['msg']}"
