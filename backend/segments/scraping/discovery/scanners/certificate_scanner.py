"""Certificate and key-store scanner.

Walks a target for certificate material, parses what it can in full, and
fingerprints what it must not open. Produces `certificate` and `key_reference`
assets, and correlates certificates that signed one another.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..models import ScanJob
from . import certstore
from .base import BaseScanner, ScanContext

# Preamble for reading a file's head without decoding it as a certificate.
_HEAD_BYTES = 4096


class CertificateArtefactScanner(BaseScanner):
    """Discovers certificates, signing requests, key references, and key stores."""

    source_type = ScanJob.SourceType.CERTIFICATE

    scanner_id = "certificate-store"
    name = "Certificates"
    description = (
        "Parses X.509 certificates and signing requests in full, and reports "
        "key stores and key references without opening protected material."
    )
    version = "1.0.0"
    supported_targets = ("folder", "workspace")
    supported_artifacts = ("certificate", "key_reference", "library", "protocol")
    capabilities = (
        "read_only",
        "evidence_capture",
        "unbounded_coverage",
        "x509_parsing",
        "chain_correlation",
        "never_exposes_private_keys",
    )
    configuration_schema: dict[str, dict] = {}
    status = "available"

    PROGRESS_EVERY = 25
    # A certificate, request, or key store is small. Anything larger is not one,
    # and is reported as skipped rather than silently truncated.
    HARD_FILE_CAP = 64 * 1024 * 1024

    def run(self, context: ScanContext | None = None) -> list[dict]:
        from .platform import get_scan_limits, prune_names_for, resolve_scan_roots

        limits = get_scan_limits(self.scan_job)
        prune = prune_names_for(self.scan_job)
        roots = resolve_scan_roots(self.scan_job)
        if not roots:
            return []

        if context:
            context.report("enumerating", 0, None)

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
                    full = os.path.join(dirpath, name)
                    try:
                        real = os.path.realpath(full)
                    except OSError:
                        continue
                    if real in seen:
                        continue
                    suffix = Path(name).suffix.lower()
                    try:
                        with open(full, "rb") as handle:
                            head = handle.read(_HEAD_BYTES)
                    except OSError:
                        if context:
                            context.record_skip("unreadable")
                        continue
                    if not certstore.looks_like_candidate(suffix, head):
                        continue
                    seen.add(real)
                    # Carry the owning root so the location is correct even when
                    # a quick or whole scan resolves dozens of roots.
                    candidates.append((full, os.path.join(target.label, os.path.relpath(full, root))))
                    if limits.max_files is not None and len(candidates) >= limits.max_files:
                        break
                if limits.max_files is not None and len(candidates) >= limits.max_files:
                    break

        if context:
            context.report("enumerating", len(candidates), len(candidates) or None)

        findings: list[dict] = []
        certificate_details: list[dict] = []

        for index, (full, location) in enumerate(candidates, start=1):
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

            result = certstore.discover(location, data)
            # `location` is a display label in quick/whole scope, so record the
            # real path too for anything that needs to re-read the artefact.
            for group in (result.certificates, result.key_references, result.stores):
                for finding in group:
                    finding.setdefault("source_path", full)
            findings.extend(result.certificates)

            findings.extend(result.key_references)
            findings.extend(result.stores)
            certificate_details.extend(
                finding["evidence"]
                for finding in result.certificates
                if finding["evidence"].get("type") == "x509"
            )

            if not (result.certificates or result.key_references or result.stores):
                # Only an unreadable format is a coverage gap. A file that was
                # read successfully and simply held no key material is a clean
                # negative, and counting it as a skip would turn every normal
                # ~/.gnupg sweep into a false PARTIAL report.
                if context and result.skipped not in ("no_certificate_or_key_material", ""):
                    context.record_skip(result.skipped)
                continue

            if context and index % self.PROGRESS_EVERY == 0:
                context.report("inspecting", index, len(candidates))

        if context:
            context.report("inspecting", len(candidates), len(candidates) or None)

        # Correlate: a certificate whose issuer was also found here is recorded
        # as a chain link rather than two unrelated certificates.
        pairs = certstore.chain_pairs(certificate_details)
        for leaf, issuer in pairs:
            findings.append(
                {
                    "location": leaf[:64],
                    "kind": "certificate",
                    "family": "unknown",
                    "algorithm": "Issuer relationship",
                    "library": "X.509",
                    "confidence": 0.8,
                    "evidence": {
                        "type": "certificate_chain",
                        "detector": "certificate_store",
                        "value": leaf,
                        "issuer_fingerprint": issuer,
                    },
                }
            )
        return findings
