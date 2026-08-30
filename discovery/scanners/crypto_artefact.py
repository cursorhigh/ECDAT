"""Crypto-artefact scanner (hand-off skeleton for the security engineer).

WHAT THIS IS
------------
This is the dedicated "space" for the real scanning implementation. Replace
the placeholder `_extract_artefacts()` below with the actual logic that walks
crypto artefacts.

WHICH ARTEFACTS WE CARE ABOUT
-----------------------------
Mostly offline targets — internal & external apps/products/infrastructure —
containing any of:

  * algorithms        RSA, ECC, AES, DSA, DH, hash (SHA/MD5), MAC/HMAC, PQC...
  * keys / key pairs  private & public keys, key sizes, curves (P-256, Ed25519...)
  * certificates/PKI  X.509 certs, trust stores, CA chains, expiry
  * protocols         TLS versions, SSH, IKEv2, Kerberos, mTLS...
  * libraries         crypto libraries + resolved versions (OpenSSL, BoringSSL,
                      mbedTLS, libgcrypt, rustls, cryptography, NSS...)
  * hardware modules  HSM / TPM / secure enclaves / smartcards
  * cloud services    KMS, ACM, Secrets Manager, key vaults

HOW A FINDING DICT IS MADE
--------------------------
`run()` walks the target directory (per the ScanJob config) and feeds each
file path to `_extract_artefacts(path, scan_job)`. That function must return a
list of *raw finding dicts*. The rest of the pipeline (ingest -> normalize ->
classify -> correlate) is already wired and needs no changes.

Raw finding dict schema (all optional except a sensible `family`/`algorithm`):
{
    "location":     "relative file path or asset reference",
    "family":       "rsa|ecc|aes|dsa|dh|hash|mac|pqc|unknown",
    "algorithm":    "RSA", "ECDSA", "AES", "SHA-256", "ML-KEM"...
    "key_size":     2048,                     # optional
    "curve":        "P-256", "Ed25519",       # optional
    "protocol":     "TLS 1.2", "SSH",         # optional
    "library":      "OpenSSL",                # optional
    "library_version": "3.0.8",               # optional
    "confidence":   0.8,                      # 0..1
    # ...any extra keys you want (owner, raw, line numbers, cert meta)
}

Unknown/unmapped families are handled by the normalizer (it guesses from the
algorithm name), so you do not need to be exhaustive — just be accurate.
"""

import os
from pathlib import Path

from ..models import ScanJob
from .base import BaseScanner

# Default walking limits; tune via ScanJob.config, e.g.:
#   {"extensions": [".java", ".go", ".py"], "max_files": 5000, "max_depth": 20}
DEFAULT_EXTENSIONS = [
    ".java", ".go", ".py", ".js", ".ts", ".c", ".cpp", ".h", ".rs",
    ".cs", ".rb", ".php", ".kt", ".xml", ".yml", ".yaml", ".json", ".toml",
    ".pem", ".crt", ".cer", ".key", ".p12", ".jks", ".properties",
]
MAX_FILES = 10_000
MAX_DEPTH = 32


class CryptoArtefactScanner(BaseScanner):
    """Walks a local target and emits crypto-artefact raw findings.

    Client of the endpoint does not need this class directly; it is selected
    automatically via SCANNER_REGISTRY for `source_code` targets. Set the
    scan's `target` to a folder / repo / library root.
    """

    source_type = ScanJob.SourceType.SOURCE_CODE

    def run(self) -> list[dict]:
        target = (self.scan_job.target or "").strip()
        config = self.scan_job.config or {}

        path = Path(target).expanduser()
        if not path.is_dir():
            return self._extract_artefacts(target, path, config) or []

        extensions = {e.lower() for e in config.get("extensions") or DEFAULT_EXTENSIONS}
        max_files = int(config.get("max_files") or MAX_FILES)
        max_depth = int(config.get("max_depth") or MAX_DEPTH)

        findings: list[dict] = []
        scanned = 0
        root_depth = len(path.parts)

        for dirpath, dirnames, filenames in os.walk(path):
            depth = len(Path(dirpath).parts) - root_depth
            if depth > max_depth:
                dirnames[:] = []
                continue
            # Skip VCS / build / dependency dirs by default.
            dirnames[:] = [d for d in dirnames if not d.startswith((".", "node_modules", "venv"))]
            for name in filenames:
                if scanned >= max_files:
                    return findings
                if Path(name).suffix.lower() not in extensions:
                    continue
                full = os.path.join(dirpath, name)
                scanned += 1
                rel = os.path.relpath(full, target)
                findings.extend(self._extract_artefacts(rel, full, config) or [])

        return findings

    def _extract_artefacts(self, rel_path: str, full_path: str, config: dict) -> list[dict]:
        """FRIEND: implement real extraction here.

        Given a single file (`rel_path` is relative to the scan target,
        `full_path` is the absolute path), return any crypto-artefact raw
        finding dicts discovered in it.

        Current placeholder returns a single low-confidence shell record so the
        pipeline can be exercised end to end; replace this body.

        Args:
            rel_path:  path relative to the scan target (for `location`).
            full_path: absolute path you can actually read/open.
            config:    the ScanJob.config dict (extensions, max_files, ...).

        Returns:
            list of raw finding dicts (see module docstring for schema).
        """
        # TODO(security): implement your real scanner here.
        # Example shape to get started:
        return [
            {
                "location": rel_path,
                "family": "unknown",
                "algorithm": "",
                "confidence": 0.1,
            }
        ]
