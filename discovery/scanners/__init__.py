"""Scanner registry: maps source types to concrete scanner classes."""

from ..models import ScanJob
from .base import BaseScanner
from .demo import DemoScreenshotScanner
from .source_code import SourceCodeScanner

SCANNER_REGISTRY = {
    ScanJob.SourceType.SOURCE_CODE: SourceCodeScanner,
}

# Demo scanners can extend the registry at runtime.
DEMO_SCANNER_REGISTRY = {
    ScanJob.SourceType.SOURCE_CODE: DemoScreenshotScanner,
}


def get_scanner(scan_job: ScanJob) -> BaseScanner:
    """Return the appropriate scanner instance for a ScanJob."""
    from django.conf import settings

    source_type = scan_job.source_type

    if settings.ECDAT.get("DEMO_MODE") and source_type in DEMO_SCANNER_REGISTRY:
        if scan_job.target.lower().startswith("demo:"):
            return DEMO_SCANNER_REGISTRY[source_type](scan_job)

    cls = SCANNER_REGISTRY.get(source_type)
    if cls is None:
        raise NotImplementedError(f"No scanner registered for source_type={source_type}")
    return cls(scan_job)
