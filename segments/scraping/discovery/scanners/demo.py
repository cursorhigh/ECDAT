"""Demo mode scanner.

Emits a rich, realistic synthetic dataset so the discovery pipeline and
dashboard are immediately presentable without a live fleet. Enabled only
when settings.ECDAT['DEMO_MODE'] is on and the source is flagged as demo.
Supports both small quick demo scans and full 10,000-asset enterprise distribution seeding.
"""

from ..models import ScanJob
from .base import BaseScanner

# User-defined exact distribution counts for enterprise demo dataset
ALGORITHM_DISTRIBUTION = [
    ("ecc", "ECDSA", 256, "P-256", "TLS 1.3", "OpenSSL", "3.0.8", 1046),
    ("aes", "AES", 256, "", "GCM", "cryptography", "41.0", 1028),
    ("hash", "SHA-384", 384, "", "", "OpenSSL", "3.0.8", 1010),
    ("ecc", "ECC", 256, "secp256k1", "TLS 1.2", "BoringSSL", "1.0", 1009),
    ("ecc", "ECDH", 256, "P-256", "TLS 1.3", "OpenSSL", "3.0.8", 1005),
    ("hash", "SHA-256", 256, "", "", "OpenSSL", "3.0.8", 1004),
    ("hash", "SHA-512", 512, "", "", "OpenSSL", "3.0.8", 988),
    ("3des", "3DES", 168, "", "TLS 1.0", "mbedTLS", "2.16.9", 987),
    ("rsa", "RSA", 2048, "", "TLS 1.2", "OpenSSL", "3.0.8", 977),
    ("dsa", "DSA", 1024, "", "SSH", "OpenSSH", "9.3", 946),
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
    "crypto/hsm-bridge",
    "cloud/kms-adapter",
]

_FILES = [
    "src/main/java/com/enterprise/crypto/CryptoConfig.java",
    "src/security/cipher_service.py",
    "pkg/auth/tls_handshake.go",
    "src/utils/hashing.cpp",
    "config/ssl_context.xml",
]


def generate_enterprise_demo_findings(full_distribution: bool = True) -> list[dict]:
    """Generates synthetic findings based on algorithm distribution."""
    out = []
    global_idx = 0

    if not full_distribution:
        # Generate small quick sample (~20 items)
        for family, algo, key, curve, proto, lib, ver, _ in ALGORITHM_DISTRIBUTION:
            repo = _REPOS[global_idx % len(_REPOS)]
            filePath = _FILES[global_idx % len(_FILES)]
            out.append({
                "location": f"{repo}/{filePath}",
                "family": family,
                "algorithm": algo,
                "key_size": key,
                "curve": curve,
                "protocol": proto,
                "library": lib,
                "library_version": ver,
                "confidence": 0.9 if global_idx % 3 == 0 else 0.8,
                "demo": True,
            })
            global_idx += 1
        return out

    # Generate full 9,995 item distribution
    for family, algo, key, curve, proto, lib, ver, count in ALGORITHM_DISTRIBUTION:
        for i in range(count):
            repo = _REPOS[(global_idx + i) % len(_REPOS)]
            filePath = _FILES[(global_idx + i) % len(_FILES)]

            # Vary key sizes slightly for realism
            var_key = key
            if algo == "RSA" and i % 5 == 0:
                var_key = 4096 if i % 10 == 0 else 1024
            elif algo == "AES" and i % 4 == 0:
                var_key = 128

            out.append({
                "location": f"{repo}/{filePath}#L{10 + (i % 250)}",
                "family": family,
                "algorithm": algo,
                "key_size": var_key,
                "curve": curve,
                "protocol": proto,
                "library": lib,
                "library_version": ver,
                "confidence": 0.95 if i % 4 == 0 else 0.85,
                "demo": True,
            })
            global_idx += 1

    return out


class DemoScreenshotScanner(BaseScanner):
    """Synthetic source-code scanner used in DEMO_MODE."""

    source_type = ScanJob.SourceType.SOURCE_CODE

    def __init__(self, scan_job: ScanJob = None, full_distribution: bool = True):
        super().__init__(scan_job)
        self.full_distribution = full_distribution

    def run(self) -> list[dict]:
        return generate_enterprise_demo_findings(full_distribution=self.full_distribution)
