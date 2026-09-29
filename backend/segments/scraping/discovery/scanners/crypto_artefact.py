"""Crypto-artefact scanner (real discovery engine).

Uses the ECDAT YARA rule engine (crypto_rules.yar, via crypto_scan.yara_engine)
to detect cryptographic artefacts — algorithms, keys, hashes, protocols,
libraries, post-quantum primitives — in local targets. Emits raw finding dicts
in the discovery schema so the shared pipeline picks them up:

    scan -> intake (raw findings) -> normalize -> classify -> correlate (graph)

The set of directories scanned is decided per-OS and per-scope by
``discovery.scanners.platform``:

    quick     -> curated high-yield platform locations (SSH, system PKI,
                 key containers, keystores, developer credentials) + workspace
    whole     -> every drive / filesystem root (aggressive prunes + hard caps)
    specified -> the exact folder the user chose

Raw finding dict schema:
{
    "location":     "display path (label + relative path under the root)",
    "family":       "rsa|ecc|aes|dsa|dh|hash|mac|pqc|unknown",
    "algorithm":    "RSA", "ECC", "AES", "MD5", "PQC", "TLS", "BoringSSL"...
    "key_size":     optional
    "curve":        optional
    "protocol":     optional
    "library":      optional
    "library_version": optional
    "confidence":   0.0-1.0
}
"""

import os
from pathlib import Path

from ..models import ScanJob
from . import dependency, sourceapi, x509
from . import keymaterial
from .base import BaseScanner, ScanContext
from .platform import (
    RootTarget,
    get_scan_limits,
    prune_names_for,
    resolve_scan_roots,
)

# Default walking limits; tune via ScanJob.config, e.g.:
#   {"extensions": [".java", ".go", ".py"], "max_files": 5000, "max_depth": 20}
DEFAULT_EXTENSIONS = [
    ".java", ".go", ".py", ".js", ".ts", ".c", ".cpp", ".h", ".rs",
    ".cs", ".rb", ".php", ".kt", ".xml", ".yml", ".yaml", ".json", ".toml",
    ".pem", ".crt", ".cer", ".der", ".key", ".p12", ".pfx", ".jks", ".properties",
    ".conf", ".cfg", ".ini", ".env", ".properties", ".gpg", ".kbx", ".pub", ".csr",
]


def _yara_match_to_finding(match: dict, rel_path: str) -> dict:
    """Map a YARA match dict to a discovery raw-finding dict.

    `match` comes from crypto_scan.yara_engine.match_file:
        {"rule": "...", "algorithm": "...", "kind": "...", "count": n,
         "strings": [...]}

    The `family` is derived from the rule so the normalizer/classifier can
    canonically group it. Extra context (matched strings) is preserved under
    `raw` so downstream viewers can show evidence.
    """
    rule = (match.get("rule") or "").strip()
    algo = (match.get("algorithm") or "").strip()
    kind = (match.get("kind") or "").strip()
    count = int(match.get("count") or 0)

    meta = _RULE_META.get(rule, {})
    family = meta.get("family", "unknown")
    confidence = float(meta.get("confidence", 0.6))

    finding = {
        "location": rel_path,
        "kind": _yara_kind(kind, rule, algo),
        "family": family,
        "algorithm": algo or meta.get("algorithm", ""),
        "confidence": confidence,
        "evidence": {
            "type": "yara_signature",
            "detector": "crypto_rules",
            "value": rule,
            "match_count": count,
        },
    }
    if kind == "protocol" or (meta.get("protocol")):
        finding["protocol"] = meta.get("protocol", algo)
    if kind == "library" or (meta.get("library")):
        finding["library"] = meta.get("library", algo) or algo
    if count:
        finding["raw"] = {"matches": count, "strings": match.get("strings", [])[:8]}
    return finding


def _yara_kind(kind: str, rule: str, algorithm: str) -> str:
    """Canonical artefact kind for a signature match.

    The engine's `kind` is a match-type hint from the rule file ("public_key",
    "protocol", "library") and is not one of the canonical kinds. It is only
    trusted for protocol/library, where it is the only signal available; for
    certificates and key material the rule name is authoritative, because a
    generic rule like `Crypto_RSA` is also tagged "public_key" and would
    otherwise be reported as a key reference.
    """
    hint = (kind or "").lower()
    name = (rule or "").lower()
    algo = (algorithm or "").lower()

    if "certificate" in name or "x509" in algo or "certificate" in hint:
        return "certificate"
    if "privatekey" in name or "private_key" in hint or "-private" in algo:
        return "key"
    if "publickey" in name or "openssl_private" in name:
        return "key_reference"
    if "library" in hint or "library" in name or "boringssl" in algo:
        return "library"
    if "protocol" in hint or algo.startswith("tls"):
        return "protocol"
    if "pkcs12" in name or "pgp" in name:
        return "key_reference"
    return "algorithm"


# Map each YARA rule to canonical discovery fields (family + confidence +
# optional protocol/library). Tunable by the security engineer.
_RULE_META = {
    "Crypto_RSA":              {"family": "rsa",   "algorithm": "RSA",      "confidence": 0.90},
    "Crypto_ECC":              {"family": "ecc",   "algorithm": "ECC",      "confidence": 0.85},
    "Crypto_AES":              {"family": "aes",   "algorithm": "AES",      "confidence": 0.85},
    "Crypto_Hash":             {"family": "hash",  "algorithm": "HASH",     "confidence": 0.80},
    "Crypto_WeakHash_MD5":     {"family": "hash",  "algorithm": "MD5",      "confidence": 0.90},
    "Crypto_PostQuantum":      {"family": "pqc",   "algorithm": "PQC",      "confidence": 0.85},
    "Crypto_TLS":              {"family": "unknown", "algorithm": "TLS",   "protocol": "TLS", "confidence": 0.75},
    "Crypto_Library_BoringSSL": {"family": "unknown", "algorithm": "BoringSSL",
                                 "library": "BoringSSL", "confidence": 0.70},
    # Platform/key-material rules (added so cert/key/SSH stores actually match)
    "Crypto_Certificate_RSA":  {"family": "rsa",   "algorithm": "X509-RSA",  "confidence": 0.80},
    "Crypto_Certificate_EC":   {"family": "ecc",   "algorithm": "X509-EC",   "confidence": 0.80},
    "Crypto_PrivateKey_RSA":   {"family": "rsa",   "algorithm": "RSA-private", "confidence": 0.90},
    "Crypto_PrivateKey_EC":    {"family": "ecc",   "algorithm": "EC-private", "confidence": 0.90},
    "Crypto_PrivateKey_DSA":   {"family": "dsa",   "algorithm": "DSA-private", "confidence": 0.90},
    "Crypto_PrivateKey_OpenSSH": {"family": "unknown", "algorithm": "OpenSSH-private", "confidence": 0.75},
    "Crypto_SSH_RSA":          {"family": "rsa",   "algorithm": "RSA-SSH",   "confidence": 0.85},
    "Crypto_SSH_ECDSA":        {"family": "ecc",   "algorithm": "ECDSA-SSH", "confidence": 0.85},
    "Crypto_SSH_Ed25519":      {"family": "ecc",   "algorithm": "Ed25519-SSH", "confidence": 0.85},
    "Crypto_SSH_DSA":          {"family": "dsa",   "algorithm": "DSA-SSH",   "confidence": 0.85},
    "Crypto_OpenPGP":          {"family": "unknown", "algorithm": "OpenPGP", "confidence": 0.70},
    "Crypto_PKCS12":           {"family": "unknown", "algorithm": "PKCS12",  "confidence": 0.70},
    "Crypto_DH_Parameters":    {"family": "dh",    "algorithm": "DH",        "confidence": 0.80},
}


class CryptoArtefactScanner(BaseScanner):
    """Walks local targets and detects crypto artefacts with YARA.

    Selected automatically via SCANNER_REGISTRY for `source_code` targets.
    The scope (quick/whole/specified) and the operating system decide which
    roots are walked (see discovery.scanners.platform).
    """

    source_type = ScanJob.SourceType.SOURCE_CODE

    scanner_id = "source-discovery"
    name = "Source discovery"
    description = (
        "Inspects files on an approved location for cryptographic algorithms, "
        "key material, certificates, protocols, and library references."
    )
    version = "1.0.0"
    supported_targets = ("workspace", "folder")
    supported_artifacts = (
        "algorithm",
        "key",
        "certificate",
        "protocol",
        "library",
        "dependency",
        "crypto_api",
        "crypto_configuration",
        "key_reference",
        "cloud_crypto_service",
    )
    capabilities = (
        "read_only",
        "evidence_capture",
        "unbounded_coverage",
        "x509_parsing",
        "python_ast",
        "dependency_resolution",
        "config_parsing",
        "key_reference_detection",
    )
    # No limits are exposed: discovery covers the whole target by default so
    # nothing is silently truncated. A caller can still pass an explicit
    # max_files / max_depth / max_file_size through ScanJob.config; when one is
    # hit the job reports PARTIAL with the reason instead of claiming success.
    configuration_schema: dict[str, dict] = {}
    status = "available"

    # Progress is published at most this often while inspecting.
    PROGRESS_EVERY = 25

    def _candidates(self, roots, prune, extensions, limits):
        """Yield (full_path, location) for every file this scan will inspect.

        Shared by the counting pass and the inspecting pass so both agree on
        exactly which files are in scope.
        """
        for target in roots:
            root = target.root
            root_depth = len(Path(root).parts)

            for dirpath, dirnames, filenames in os.walk(root):
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
                    if not target.scan_all and Path(name).suffix.lower() not in extensions:
                        continue
                    yield full, os.path.join(target.label, os.path.relpath(full, root))

    def run(self, context: ScanContext | None = None) -> list[dict]:
        """Walk the resolved roots and return detected crypto-artefact findings.

        Runs in two passes: a cheap directory-only pass to establish a real
        denominator, then the inspecting pass. That makes the reported progress
        measured rather than a fixed ladder, and lets cancellation land during
        enumeration as well as inspection.
        """
        config = self.scan_job.config or {}

        roots = resolve_scan_roots(self.scan_job)
        if not roots:
            # No profile root exists (e.g. bare CI box) -> fall back to the
            # project directory so a quick/whole scan still does something.
            from django.conf import settings

            base = Path(getattr(settings, "BASE_DIR", Path("."))).resolve()
            roots = [RootTarget(root=str(base), label=str(base))]

        limits = get_scan_limits(self.scan_job)
        prune = prune_names_for(self.scan_job)
        extensions = {e.lower() for e in config.get("extensions") or DEFAULT_EXTENSIONS}

        if context:
            context.report("enumerating", 0, None)

        # Pass 1: count what is in scope so progress is a true ratio.
        total = 0
        for _ in self._candidates(roots, prune, extensions, limits):
            total += 1
            if context and total % 200 == 0:
                context.check_cancelled()
        if limits.max_files is not None and total > limits.max_files:
            if context:
                context.record_skip("file_limit", total - limits.max_files)
            total = limits.max_files

        findings: list[dict] = []
        seen_paths: set[str] = set()
        scanned = 0

        # Pass 2: inspect.
        for full, location in self._candidates(roots, prune, extensions, limits):
            if limits.max_files is not None and scanned >= limits.max_files:
                break
            if context:
                context.check_cancelled()

            real = os.path.realpath(full)
            if real in seen_paths:
                continue
            seen_paths.add(real)

            if limits.max_file_size is not None:
                try:
                    if os.path.getsize(full) > limits.max_file_size:
                        if context:
                            context.record_skip("file_too_large")
                        continue
                except OSError:
                    if context:
                        context.record_skip("unreadable")
                    continue

            scanned += 1
            found, skipped = self._extract_artefacts(location, full, config)
            # Stamp the real path centrally: `location` is a display label in
            # quick/whole scope, so downstream stages cannot re-read the file
            # without this.
            for finding in found:
                finding.setdefault("source_path", full)
            findings.extend(found)
            if skipped and context:
                context.record_skip(skipped)

            if context and scanned % self.PROGRESS_EVERY == 0:
                context.report("inspecting", scanned, total)

        if context:
            context.report("inspecting", scanned, total or None)
        return findings

    # Text-ish files are decoded and fed to the structured detectors; binary
    # files go to YARA only.
    TEXT_SUFFIXES = {
        ".py", ".pyi", ".go", ".java", ".kt", ".kts", ".js", ".mjs", ".cjs",
        ".jsx", ".ts", ".tsx", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".rb",
        ".php", ".rs", ".scala", ".swift", ".m", ".mm", ".pl", ".lua", ".dart",
        ".sh", ".bash", ".ps1", ".conf", ".cfg", ".ini", ".cnf", ".yaml", ".yml",
        ".toml", ".json", ".xml", ".properties", ".env", ".txt", ".pem", ".crt",
        ".cer", ".der", ".csr", ".key", ".pub", ".jks", ".p12", ".pfx", ".gpg",
        ".keystore", ".truststore", ".cnf", ".sql",
    }
    # Binary key stores are identified by magic bytes, never read as text.
    KEYLIKE_SUFFIXES = {".pkcs12", ".p12", ".pfx", ".jks", ".keystore"}

    MAX_TEXT_BYTES = 8 * 1024 * 1024

    def _extract_artefacts(self, location: str, full_path: str, config: dict) -> tuple[list[dict], str | None]:
        """Detect crypto artefacts in one file.

        Returns (findings, skip_reason). A file that could not be inspected
        yields a reason instead of silently contributing nothing, so the job
        can report PARTIAL rather than a false success.
        """
        # Lazy import to avoid any load-order coupling between discovery and
        # crypto_scan at import time (the rules compile on first use).
        from segments.scraping.crypto_scan.yara_engine import match_file

        findings: list[dict] = []
        suffix = Path(full_path).suffix.lower()
        filename = os.path.basename(full_path)

        # 1. Structured detection: certificates, keys, source, config, manifests.
        #    A crash in any one detector must cost only this file, not the whole
        #    scan, so it is isolated exactly like the YARA pass below.
        if suffix in self.TEXT_SUFFIXES or filename in sourceapi.MANIFEST_FILES:
            text, skip = self._read_text(full_path, suffix)
            if skip:
                return [], skip
            try:
                findings.extend(self._run_detectors(location, filename, text, full_path))
            except Exception as exc:  # noqa: BLE001
                # Includes RecursionError from deeply nested JSON manifests.
                return findings, f"inspect_error:{type(exc).__name__}"
        elif not suffix:
            # Extension-less files (real SSH keys, /etc/ssl files) still matter.
            # Only the high-precision detectors run, because both key and
            # certificate recognition require an exact magic header and so
            # cannot fire on binary content.
            try:
                findings.extend(self._detect_embedded_material(location, full_path))
            except Exception as exc:  # noqa: BLE001
                return findings, f"inspect_error:{type(exc).__name__}"

        # 2. YARA signature pass, kept for coverage the detectors do not model.
        try:
            matches = match_file(full_path)
        except OSError:
            return findings, "unreadable"
        except Exception as exc:  # noqa: BLE001
            # Surface the real cause rather than filing it under "unreadable":
            # a crash in a detector is a different, actionable problem from a
            # file we could not open, and the job reports it as PARTIAL.
            return findings, f"yara_error:{type(exc).__name__}"

        existing = {(f.get("kind"), f.get("algorithm"), f.get("line")) for f in findings}
        # A certificate already parsed properly by the x509 detector must not be
        # reported a second time from a signature that only guessed at it.
        parsed_cert = any(
            (f.get("evidence") or {}).get("type") == "x509" for f in findings
        )
        for m in matches:
            candidate = _yara_match_to_finding(m, location)
            if parsed_cert and candidate.get("kind") == "certificate":
                continue
            key = (candidate.get("kind"), candidate.get("algorithm"), candidate.get("line"))
            if key in existing:
                continue
            existing.add(key)
            findings.append(candidate)

        return findings, None

    def _read_text(self, full_path: str, suffix: str) -> tuple[str, str | None]:
        """Read a file for text analysis, refusing key stores and oversized files."""
        if suffix in self.KEYLIKE_SUFFIXES:
            return "", None
        try:
            size = os.path.getsize(full_path)
        except OSError:
            return "", "unreadable"
        if size > self.MAX_TEXT_BYTES:
            return "", "file_too_large"
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as handle:
                return handle.read(), None
        except OSError:
            return "", "unreadable"

    def _detect_embedded_material(self, location: str, full_path: str) -> list[dict]:
        """Certificate/key recognition for files the text pipeline will not read.

        Both checks need an exact header, so running them on an unknown binary
        is safe. The key path still reports a fingerprint only.
        """
        findings: list[dict] = []
        magic = self._read_magic(full_path)
        if not magic:
            return findings

        head = b""
        try:
            with open(full_path, "rb") as handle:
                head = handle.read(4096)
        except OSError:
            return findings

        classified = keymaterial.classify_key_blob(head)
        if classified:
            family, kind = classified
            findings.append(
                {
                    "location": location,
                    "kind": "key" if kind == "private_key" else "key_reference",
                    "family": {"rsa": "rsa", "dsa": "dsa", "ec": "ecc"}.get(family, "unknown"),
                    "algorithm": family.upper() if family in ("rsa", "dsa", "ec") else "",
                    "library": kind,
                    "confidence": 0.9,
                    "evidence": {
                        "type": "key_fingerprint",
                        "detector": "keymaterial",
                        "value": keymaterial.fingerprint(head),
                        "key_kind": kind,
                    },
                    "strength": "private_key_material" if kind == "private_key" else None,
                }
            )
        return findings

    def _parse_manifest(self, filename: str, text: str, location: str) -> list[dict]:
        """Parse a manifest into findings, one per cryptographically-relevant package.

        Non-crypto dependencies are not reported as findings: they are recorded
        as `Dependency` rows so the dependency graph is complete, but a finding
        should mean "this is cryptographic", not "this file listed something".
        """
        findings: list[dict] = []
        for dep in dependency.parse_manifest(filename, text):
            info = dependency.classify_dependency(dep)
            if not info["is_crypto"]:
                continue
            findings.append(
                {
                    "kind": "dependency",
                    "family": info["family"] if info["family"] != "unknown" else "unknown",
                    "algorithm": "",
                    "library": dep.package,
                    "library_version": dep.version,
                    "confidence": 0.95,
                    "line": dep.line,
                    "evidence": {
                        "type": "manifest_entry",
                        "detector": "dependency_parser",
                        "value": f"{dep.package}@{dep.version}" if dep.version else dep.package,
                        "ecosystem": dep.ecosystem,
                        "scope": dep.scope,
                        "relevance": info["relevance"],
                        "capability": info["capability"],
                        "manifest": filename,
                        **({"key_service": info["system"]} if info.get("system") else {}),
                    },
                }
            )
        return findings

    @staticmethod
    def _read_magic(full_path: str) -> bytes:
        """First bytes of a file, for container-type sniffing."""
        try:
            with open(full_path, "rb") as handle:
                return handle.read(8)
        except OSError:
            return b""

    def _run_detectors(self, location: str, filename: str, text: str, full_path: str) -> list[dict]:
        """Run every structured detector over one file's text."""
        findings: list[dict] = []

        def emit(partial: dict) -> None:
            partial.setdefault("location", location)
            partial.setdefault("family", "unknown")
            partial.setdefault("algorithm", "")
            partial.setdefault("confidence", 0.6)
            findings.append(partial)

        # Certificates: real X.509 parsing, not string matching.
        if x509.looks_like_certificate(text.encode("utf-8", errors="replace")):
            for detail in x509.load_certificates(text.encode("utf-8", errors="replace")):
                algorithm = detail.public_key_algorithm
                family = {
                    "RSA": "rsa", "EC": "ecc", "DSA": "dsa",
                    "Ed25519": "ecc", "Ed448": "ecc",
                }.get(algorithm, "unknown")
                strength = (
                    "expired" if detail.expired
                    else "key_below_2048" if x509.is_weak_key(algorithm, detail.key_size)
                    else None
                )
                emit({
                    "kind": "certificate",
                    "family": family,
                    "algorithm": algorithm,
                    "key_size": detail.key_size,
                    "curve": detail.curve,
                    "library": "X.509",
                    "confidence": 0.98,
                    "evidence": {"type": "x509", "detector": "cryptography", "value": detail.sha256_fingerprint, **detail.as_evidence()},
                    "strength": strength,
                })

        # Key material: fingerprint and type only, never the key.
        classified = keymaterial.classify_key_blob(text.encode("utf-8", errors="replace"))
        if classified:
            family, kind = classified
            emit({
                "kind": "key_reference" if kind == "public_key" else "key",
                "family": {"rsa": "rsa", "dsa": "dsa", "ec": "ecc"}.get(family, "unknown"),
                "algorithm": family.upper() if family and family not in ("encrypted", "openssh", "pgp") else "",
                "library": kind,
                "confidence": 0.95,
                "evidence": {
                    "type": "key_fingerprint",
                    "detector": "keymaterial",
                    "value": keymaterial.fingerprint(text.encode("utf-8", errors="replace")),
                    "key_kind": kind,
                },
                "strength": "private_key_material" if kind == "private_key" else None,
            })

        keystore = keymaterial.keystore_type(self._read_magic(full_path))
        if keystore:
            emit({
                "kind": "key_reference",
                "family": "unknown",
                "library": keystore,
                "confidence": 0.8,
                "evidence": {"type": "keystore_container", "detector": "keymaterial", "value": keystore},
            })

        # Dependency manifests, parsed per ecosystem rather than substring-matched.
        if dependency.ecosystem_for(filename):
            for dep in self._parse_manifest(filename, text, location):
                emit(dep)

        # Source: real AST for Python, curated symbols elsewhere.
        if filename.endswith((".py", ".pyi")):
            for hit in sourceapi.detect_python(text):
                emit(hit)
        else:
            for hit in sourceapi.detect_symbols(text):
                emit(hit)

        # Structured configuration manifests (JSON, YAML)
        if filename.endswith((".json", ".yaml", ".yml")):
            for hit in sourceapi.detect_structured_config(text, filename):
                emit(hit)

        # Configuration directives, only for files that can actually hold them.
        if Path(filename).suffix.lower() in sourceapi.CONFIG_SUFFIXES and not filename.endswith(".json"):
            for hit in sourceapi.detect_config(text):
                emit(hit)

        # Key-management references and managed-service SDK usage, line by line.
        for index, line in enumerate(text.splitlines(), start=1):
            if len(line) > 2000:
                line = line[:2000]
            for reference in keymaterial.find_key_references(line):
                emit({**reference, "line": index})
            for usage in keymaterial.find_kms_sdk_usage(line):
                emit({**usage, "line": index})

        return findings