"""Demo mode scanner.

Emits a rich, realistic synthetic dataset so the discovery pipeline and
dashboard are immediately presentable without a live fleet. Enabled only
when settings.ECDAT['DEMO_MODE'] is on and the source is flagged as demo.
"""

from ..models import ScanJob
from .base import BaseScanner

# (family, algorithm, key_size, curve, protocol, library)
_SAMPLES = [
    ("rsa", "RSA", 2048, "", "TLS 1.2", "OpenSSL", "3.0.8"),
    ("rsa", "RSA", 2048, "", "TLS 1.2", "OpenSSL", "3.0.8"),
    ("rsa", "RSA", 4096, "", "TLS 1.3", "OpenSSL", "3.0.8"),
    ("rsa", "RSA", 1024, "", "TLS 1.0", "mbedTLS", "2.16.9"),
    ("ecc", "ECDSA", 256, "P-256", "TLS 1.3", "OpenSSL", "3.0.8"),
    ("ecc", "ECDH", 256, "P-256", "TLS 1.3", "OpenSSL", "3.0.8"),
    ("ecc", "ECDSA", 384, "P-384", "TLS 1.2", "BoringSSL", ""),
    ("ecc", "Ed25519", 256, "Ed25519", "SSH", "OpenSSH", "9.3"),
    ("aes", "AES", 128, "", "CBC", "cryptography", "41.0"),
    ("aes", "AES", 256, "", "GCM", "cryptography", "41.0"),
    ("aes", "AES", 256, "", "GCM", "cryptography", "41.0"),
    ("hash", "SHA-1", 160, "", "", "OpenSSL", "3.0.8"),
    ("hash", "SHA-256", 256, "", "", "OpenSSL", "3.0.8"),
    ("hash", "MD5", 128, "", "", "OpenSSL", "3.0.8"),
    ("dsa", "DSA", 1024, "", "SSH", "OpenSSH", "9.3"),
    ("dh", "DH", 2048, "", "IKEv2", "libgcrypt", "1.10"),
    ("pqc", "ML-KEM", 768, "ML-KEM-768", "TLS 1.3 hybrid", "OpenSSL", "3.5"),
]

_REPOS = [
    "payments/gateway-api",
    "payments/ledger-service",
    "identity/auth-service",
    "identity/sso",
    "data/user-analytics",
    "partners/kyc-worker",
    "core/event-bus",
    "core/config-server",
]

_OWNERS = {
    "payments": "Payments",
    "identity": "Identity",
    "data": "Data Platform",
    "partners": "Partners",
    "core": "Platform Core",
}


def _build(name: str, index: int) -> dict:
    family, algo, key, curve, proto, lib, ver = _SAMPLES[index % len(_SAMPLES)]
    prefix = name.split("/")[0]
    return {
        "location": f"{name}/src/main/java/com/{prefix}/CryptoConfig.java",
        "family": family,
        "algorithm": algo,
        "key_size": key,
        "curve": curve,
        "protocol": proto,
        "library": lib,
        "library_version": ver,
        "confidence": 0.9 if index % 7 else 0.6,
        "demo": True,
    }


class DemoScreenshotScanner(BaseScanner):
    """Synthetic source-code scanner used in DEMO_MODE."""

    source_type = ScanJob.SourceType.SOURCE_CODE

    def run(self) -> list[dict]:
        out = []
        idx = 0
        for repo in _REPOS:
            n = 2 + (idx % 3)  # 2-4 findings per repo
            for _ in range(n):
                out.append(_build(repo, idx))
                idx += 1
        return out
