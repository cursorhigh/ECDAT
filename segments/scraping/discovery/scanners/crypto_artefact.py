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
from .base import BaseScanner
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
        "family": family,
        "algorithm": algo or meta.get("algorithm", ""),
        "confidence": confidence,
    }
    if kind == "protocol" or (meta.get("protocol")):
        finding["protocol"] = meta.get("protocol", algo)
    if kind == "library" or (meta.get("library")):
        finding["library"] = meta.get("library", algo) or algo
    if count:
        finding["raw"] = {"matches": count, "strings": match.get("strings", [])[:8]}
    return finding


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

    def run(self) -> list[dict]:
        """Walk the resolved roots and return detected crypto-artefact findings."""
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

        findings: list[dict] = []
        seen_paths: set[str] = set()
        scanned = 0

        for target in roots:
            if scanned >= limits.max_files:
                break

            root = target.root
            root_depth = len(Path(root).parts)

            for dirpath, dirnames, filenames in os.walk(root):
                depth = len(Path(dirpath).parts) - root_depth
                if depth > limits.max_depth:
                    dirnames[:] = []
                    continue
                dirnames[:] = sorted(
                    (d for d in dirnames if not d.startswith(".") and d not in prune),
                    key=lambda d: d.lower(),
                )

                for name in filenames:
                    if scanned >= limits.max_files:
                        break
                    full = os.path.join(dirpath, name)
                    real = os.path.realpath(full)
                    if real in seen_paths:
                        continue
                    seen_paths.add(real)

                    try:
                        if os.path.getsize(full) > limits.max_file_size:
                            continue
                    except OSError:
                        continue

                    if not target.scan_all and Path(name).suffix.lower() not in extensions:
                        continue

                    scanned += 1
                    rel = os.path.relpath(full, root)
                    location = os.path.join(target.label, rel)
                    findings.extend(self._extract_artefacts(location, full, config) or [])

                if scanned >= limits.max_files:
                    break

        return findings

    def _extract_artefacts(self, location: str, full_path: str, config: dict) -> list[dict]:
        """Detect crypto artefacts in one file using the YARA engine."""
        # Lazy import to avoid any load-order coupling between discovery and
        # crypto_scan at import time (the rules compile on first use).
        from segments.scraping.crypto_scan.yara_engine import match_file

        findings = []
        try:
            matches = match_file(full_path)
        except Exception:  # noqa: BLE001 - unreadable/unsupported files are skipped
            return []

        for m in matches:
            findings.append(_yara_match_to_finding(m, location))
        return findings