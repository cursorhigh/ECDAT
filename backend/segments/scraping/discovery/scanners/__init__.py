"""Scanner registry: maps source types to concrete scanner classes.

The registry is the single place discovery answers "what can inspect what".
`list_scanners()` reports it so the API (and therefore the UI) never has to
hard-code discovery sources, engines, or limit fields.
"""

from ..models import ScanJob
from .base import BaseScanner
from .binary_scanner import BinaryArtefactScanner
from .certificate_scanner import CertificateArtefactScanner
from .container_scanner import ContainerImageScanner
from .crypto_artefact import CryptoArtefactScanner
from .demo import DemoScreenshotScanner

SCANNER_REGISTRY = {
    ScanJob.SourceType.SOURCE_CODE: CryptoArtefactScanner,
    ScanJob.SourceType.BINARY: BinaryArtefactScanner,
    ScanJob.SourceType.CERTIFICATE: CertificateArtefactScanner,
    ScanJob.SourceType.CONTAINER: ContainerImageScanner,
}

# Demo scanners can extend the registry at runtime.
DEMO_SCANNER_REGISTRY = {
    ScanJob.SourceType.SOURCE_CODE: DemoScreenshotScanner,
}

# Source types the product recognises but has no implementation for yet. They
# are reported with status "planned" so the UI can name them honestly instead
# of offering a source that would only ever fail.
#
# A source belongs here ONLY while it has no entry in SCANNER_REGISTRY. Keeping
# a working source listed here is a latent lie: removing it from the registry
# would silently downgrade it to "planned" with no test noticing.
PLANNED_SOURCES: dict[str, dict] = {
    ScanJob.SourceType.DEPENDENCY: {
        "name": "Dependency analysis",
        "description": "Scans package manifests and lock files on their own, without "
                       "full source analysis.",
    },
    ScanJob.SourceType.HSM: {
        "name": "Hardware and key management",
        "description": "Discovers HSM, TPM, and key-management references and their metadata.",
    },
    ScanJob.SourceType.CLOUD: {
        "name": "Cloud key services",
        "description": "Discovers cloud cryptographic resources within an authorized account.",
    },
}


def _assert_planned_sources_are_unimplemented() -> None:
    """Fail fast if a working source is also advertised as planned."""
    overlap = set(PLANNED_SOURCES) & set(SCANNER_REGISTRY)
    if overlap:
        raise RuntimeError(
            "Sources are both implemented and advertised as planned: "
            + ", ".join(sorted(overlap))
        )


_assert_planned_sources_are_unimplemented()



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


def list_scanners() -> list[dict]:
    """Describe every discovery source this deployment knows about.

    The source list is derived from the registry plus the declared planned
    sources, so registering a scanner is the only step needed to make it
    appear. Registered scanners are reported as `available` with real
    metadata; unimplemented ones as `planned` with no capabilities, so callers
    can name them without implying they work.
    """
    from django.conf import settings

    demo_mode = bool(settings.ECDAT.get("DEMO_MODE"))
    described: list[dict] = []

    known = {*SCANNER_REGISTRY, *PLANNED_SOURCES}
    for source_type in ScanJob.SourceType.values:
        known.add(source_type)

    for source_type in known:
        cls = SCANNER_REGISTRY.get(source_type)
        if cls is not None:
            entry = cls.describe()
            entry["status"] = "available"
            entry["demo_supported"] = demo_mode and source_type in DEMO_SCANNER_REGISTRY
            described.append(entry)
            continue

        planned = PLANNED_SOURCES.get(source_type, {})
        described.append(
            {
                "id": source_type,
                "source_type": source_type,
                "name": planned.get("name") or str(source_type).replace("_", " ").title(),
                "description": planned.get("description", ""),
                "version": "",
                "supported_targets": [],
                "supported_artifacts": [],
                "capabilities": [],
                "configuration_schema": {},
                "status": "planned",
                "demo_supported": False,
            }
        )

    described.sort(key=lambda entry: (entry["status"] != "available", entry["name"]))
    return described
