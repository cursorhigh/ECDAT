"""Container image scanner.

Walks a target for image archives and reports the cryptographic material
inside them. Images are read as archives only: no layer is unpacked to disk and
nothing inside the image is executed.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..models import ScanJob
from . import container_image
from .base import BaseScanner, ScanContext

# Archive extensions that may hold an image.
IMAGE_SUFFIXES = {".tar", ".tar.gz", ".tgz", ".oci", ".docker"}


class ContainerImageScanner(BaseScanner):
    """Discovers certificates, crypto binaries, and key references in images."""

    source_type = ScanJob.SourceType.CONTAINER

    scanner_id = "container-image"
    name = "Container images"
    description = (
        "Reads saved container images and reports the certificates, key stores, "
        "crypto libraries, and key references they contain."
    )
    version = "1.0.0"
    supported_targets = ("folder", "file", "workspace")
    supported_artifacts = ("container", "certificate", "key_reference", "library", "protocol")
    capabilities = (
        "read_only",
        "evidence_capture",
        "unbounded_coverage",
        "layer_inspection",
        "image_metadata",
        "no_execution",
    )
    configuration_schema: dict[str, dict] = {}
    status = "available"

    PROGRESS_EVERY = 5
    HARD_FILE_CAP = 2 * 1024 * 1024 * 1024

    def run(self, context: ScanContext | None = None) -> list[dict]:
        from .platform import get_scan_limits, prune_names_for, resolve_scan_roots

        limits = get_scan_limits(self.scan_job)
        prune = prune_names_for(self.scan_job)
        roots = resolve_scan_roots(self.scan_job)
        if not roots:
            return []

        if context:
            context.report("locating", 0, None)

        candidates: list[tuple[str, str]] = []
        seen: set[str] = set()
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
                    lowered = name.lower()
                    if not (lowered.endswith(tuple(IMAGE_SUFFIXES)) or lowered.endswith(".tar.gz")):
                        continue
                    full = os.path.join(dirpath, name)
                    try:
                        real = os.path.realpath(full)
                    except OSError:
                        continue
                    if real in seen:
                        continue
                    seen.add(real)
                    candidates.append(
                        (full, os.path.join(target.label, os.path.relpath(full, root)))
                    )
                    if limits.max_files is not None and len(candidates) >= limits.max_files:
                        break
                if limits.max_files is not None and len(candidates) >= limits.max_files:
                    break

        if context:
            context.report("locating", len(candidates), len(candidates) or None)

        findings: list[dict] = []
        for index, (full, image) in enumerate(candidates, start=1):
            if context:
                context.check_cancelled()
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

            result, layout = container_image.discover(image, data, context=context)

            if not layout.is_container:
                if context:
                    context.record_skip(layout.reason or "not_an_image")
                continue

            findings.extend(result.references)
            for finding in result.references:
                finding.setdefault("source_path", full)
            for finding in result.certificates + result.binaries:
                # Members live inside the image, so the archive itself is the
                # only re-readable artefact.
                finding.setdefault("source_path", full)
            findings.extend(result.certificates)
            findings.extend(result.binaries)

            # The image itself is an asset, even when it holds no crypto.
            findings.append(
                {
                    "location": image,
                    "source_path": full,
                    "kind": "container",
                    "family": "unknown",
                    "algorithm": layout.kind,
                    "library": "container image",
                    "confidence": 0.95,
                    "evidence": {
                        "type": "container_image",
                        "detector": "container_image",
                        "value": layout.image_id or layout.tag or image,
                        "layout": layout.kind,
                        "tag": layout.tag,
                        "layers": len(layout.layers),
                        "layers_inspected": result.layers_inspected,
                        "members_inspected": result.members_inspected,
                        "certificates_found": len(
                            [c for c in result.certificates if c["evidence"].get("type") == "x509"]
                        ),
                    },
                }
            )

            if context and index % self.PROGRESS_EVERY == 0:
                context.report("inspecting", index, len(candidates))

        if context:
            context.report("inspecting", len(candidates), len(candidates) or None)
        return findings
