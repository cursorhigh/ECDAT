"""Scanner adapters for Segment A (Discovery).

Each scanner subclass knows how to inspect one source type and emit
RawFindings. For this phase scanners run synchronously; long-running
scanners can be moved to Celery later without changing their interface.
"""

from abc import ABC, abstractmethod

from ..models import RawFinding, ScanJob


class BaseScanner(ABC):
    """Interface all scanners implement."""

    source_type = ScanJob.SourceType.SOURCE_CODE

    def __init__(self, scan_job: ScanJob):
        self.scan_job = scan_job

    @abstractmethod
    def run(self) -> list[dict]:
        """Return a list of raw finding dicts for this target."""

    def ingest(self, findings: list[dict]) -> int:
        """Persist raw findings against the scan job; returns count."""
        db = self.scan_job._state.db or "default"
        count = 0
        for item in findings:
            RawFinding.objects.using(db).create(
                scan_job=self.scan_job,
                mode=self.scan_job.mode,
                source_type=self.source_type,
                location=item.get("location", ""),
                raw_json=item,
            )
            count += 1
        self.scan_job.findings_count = count
        self.scan_job.save(update_fields=["findings_count"])
        return count
