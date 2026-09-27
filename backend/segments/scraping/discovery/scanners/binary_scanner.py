"""Binary artefact scanner.

Inspects executables, shared libraries, drivers, and packaged artefacts for
cryptographic capability: which crypto symbols they link, which algorithms
their embedded key objects reference, and whether they carry certificate or
key material.

Read-only. Nothing is executed, loaded, or unpacked, so inspecting an untrusted
binary cannot run any of its code.
"""

from __future__ import annotations

from ..models import ScanJob
from . import binary as binary_mod
from .base import BaseScanner, ScanContext

# Extensions worth inspecting as binaries. Archives and packages are included
# because they carry the same compiled artefacts plus their own metadata.
BINARY_SUFFIXES = {
    ".exe", ".dll", ".so", ".dylib", ".sys", ".drv", ".ko", ".o", ".a",
    ".bin", ".elf", ".wasm", ".apk", ".jar", ".war", ".ear", ".aar",
    ".dex", ".whl", ".egg", ".pyz", ".nupkg", ".deb", ".rpm", ".app",
}


class BinaryArtefactScanner(BaseScanner):
    """Finds cryptographic capability in compiled artefacts."""

    source_type = ScanJob.SourceType.BINARY

    scanner_id = "binary-inspection"
    name = "Binary analysis"
    description = (
        "Inspects executables, libraries, drivers, and packages for linked "
        "cryptographic symbols, embedded key objects, and certificate material."
    )
    version = "1.0.0"
    supported_targets = ("folder",)
    supported_artifacts = (
        "algorithm",
        "key_reference",
        "certificate",
        "library",
        "crypto_api",
        "hardware_module",
    )
    capabilities = (
        "read_only",
        "evidence_capture",
        "unbounded_coverage",
        "format_identification",
        "symbol_extraction",
        "no_execution",
    )
    configuration_schema: dict[str, dict] = {}
    status = "available"

    PROGRESS_EVERY = 10
    # A read ceiling that applies even when no explicit limit was configured.
    # Exceeding it is reported as a skip, never silently truncated.
    HARD_FILE_CAP = 512 * 1024 * 1024

    def run(self, context: ScanContext | None = None) -> list[dict]:
        """Inspect every binary-looking file under the resolved roots."""
        from .platform import get_scan_limits, prune_names_for, resolve_scan_roots

        config = self.scan_job.config or {}
        limits = get_scan_limits(self.scan_job)
        prune = prune_names_for(self.scan_job)
        roots = resolve_scan_roots(self.scan_job)
        if not roots:
            return []

        if context:
            context.report("enumerating", 0, None)

        candidates: list[tuple[str, str]] = []
        seen: set[str] = set()
        import os
        from pathlib import Path

        for target in roots:
            root = target.root
            root_depth = len(Path(root).parts)
            for dirpath, dirnames, filenames in os.walk(root):
                if context:
                    context.check_cancelled()
                depth = len(Path(dirpath).parts) - root_depth
                if limits.max_depth is not None and depth > limits.max_depth:
                    dirnames[:] = []
                    continue
                dirnames[:] = sorted(
                    (d for d in dirnames if not d.startswith(".") and d not in prune),
                    key=lambda d: d.lower(),
                )
                for name in filenames:
                    full = os.path.join(dirpath, name)
                    suffix = Path(name).suffix.lower()
                    if suffix not in BINARY_SUFFIXES:
                        continue
                    try:
                        real = os.path.realpath(full)
                    except OSError:
                        continue
                    if real in seen:
                        continue
                    seen.add(real)
                    candidates.append((full, os.path.join(target.label, os.path.relpath(full, root))))
                    if limits.max_files is not None and len(candidates) >= limits.max_files:
                        break
                if limits.max_files is not None and len(candidates) >= limits.max_files:
                    break

        if context:
            context.report("enumerating", len(candidates), len(candidates) or None)

        findings: list[dict] = []
        for index, (full, location) in enumerate(candidates, start=1):
            if context:
                context.check_cancelled()
            # A read ceiling that silently truncates would make a partial read
            # look like a complete one, so an over-size file is a recorded
            # coverage gap rather than a quiet partial pass.
            cap = limits.max_file_size
            if cap is None or cap > self.HARD_FILE_CAP:
                cap = self.HARD_FILE_CAP
            try:
                size = os.path.getsize(full)
            except OSError:
                if context:
                    context.record_skip("unreadable")
                continue
            if size > cap:
                if context:
                    context.record_skip("file_too_large")
                continue
            try:
                with open(full, "rb") as handle:
                    data = handle.read(cap)
            except OSError:
                if context:
                    context.record_skip("unreadable")
                continue
            # The file may have grown between the size check and the read.
            if len(data) < size and context:
                context.record_skip("file_too_large")

            produced = binary_mod.findings_for(location, data, os.path.basename(full))
            for finding in produced:
                finding.setdefault("source_path", full)
            if not produced:
                # A .so or .apk with no recognisable magic is not a failure of
                # the scan, but it is not evidence of anything either.
                if context:
                    context.record_skip("unrecognised_format")
                continue
            findings.extend(produced)

            if context and index % self.PROGRESS_EVERY == 0:
                context.report("inspecting", index, len(candidates))

        if context:
            context.report("inspecting", len(candidates), len(candidates) or None)
        return findings
