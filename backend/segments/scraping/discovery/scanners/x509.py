"""X.509 certificate inspection.

Real parsing via `cryptography`, never string matching: a `BEGIN CERTIFICATE`
line inside an unrelated text file is not a certificate, and this module is how
discovery tells the difference.

Nothing here ever handles or returns private key material. Certificates are
public by definition, but a mislabelled file could contain a key alongside one,
so only certificate structures are decoded.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

_PEM_CERT = re.compile(
    rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL
)

# Extensions worth recording for cryptographic posture.
_SAN_OID = "subjectAltName"
_KEY_USAGE_OID = "keyUsage"
_EKU_OID = "extendedKeyUsage"
_BASIC_CONSTRAINTS_OID = "basicConstraints"

_WEAK_KEY_SIZES = {"rsa": 2048, "dsa": 2048, "ec": 224}


@dataclass
class CertificateDetail:
    """Everything discovery records about one certificate."""

    subject: str = ""
    issuer: str = ""
    serial: str = ""
    not_before: str = ""
    not_after: str = ""
    public_key_algorithm: str = ""
    key_size: int | None = None
    curve: str = ""
    signature_algorithm: str = ""
    san: list[str] = field(default_factory=list)
    key_usage: list[str] = field(default_factory=list)
    is_ca: bool = False
    sha256_fingerprint: str = ""
    self_signed: bool = False
    expired: bool | None = None

    def as_evidence(self) -> dict:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "serial": self.serial,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "public_key_algorithm": self.public_key_algorithm,
            "key_size": self.key_size,
            "curve": self.curve,
            "signature_algorithm": self.signature_algorithm,
            "subject_alt_names": self.san,
            "key_usage": self.key_usage,
            "is_ca": self.is_ca,
            "sha256_fingerprint": self.sha256_fingerprint,
            "self_signed": self.self_signed,
            "expired": self.expired,
        }


def _name(value) -> str:
    try:
        return value.rfc4514_string()
    except Exception:  # noqa: BLE001 - a malformed name must not kill the scan
        return "<unparseable>"


def _public_key_detail(public_key) -> tuple[str, int | None, str]:
    from cryptography.hazmat.primitives.asymmetric import (
        dsa,
        ec,
        ed25519,
        ed448,
        rsa,
    )

    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size, ""
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size, ""
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "EC", public_key.curve.key_size, public_key.curve.name
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, "ed25519"
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", 456, "ed448"
    return type(public_key).__name__, None, ""


def _general_names(cert) -> list[str]:
    from cryptography import x509

    try:
        ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
    except (x509.ExtensionNotFound, ValueError):
        return []
    names = []
    for entry in ext.value:
        value = getattr(entry, "value", None)
        if value is not None:
            names.append(str(value))
    return names


def _extension(cert, oid: str) -> str | None:
    from cryptography import x509

    try:
        return str(cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(oid)).value)
    except (x509.ExtensionNotFound, ValueError, KeyError):
        return None


def _key_usage(cert) -> list[str]:
    from cryptography import x509

    try:
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return []
    flags = []
    for name in (
        "digital_signature",
        "content_commitment",
        "key_encipherment",
        "data_encipherment",
        "key_agreement",
        "key_cert_sign",
        "crl_sign",
    ):
        try:
            if getattr(usage, name):
                flags.append(name)
        except ValueError:
            continue
    return flags


def load_certificates(data: bytes) -> list[CertificateDetail]:
    """Parse every X.509 certificate in `data` (PEM bundle or single DER)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    details: list[CertificateDetail] = []

    blocks = _PEM_CERT.findall(data)
    certificates = []
    for block in blocks:
        try:
            certificates.append(x509.load_pem_x509_certificate(block))
        except Exception:  # noqa: BLE001 - a malformed block is simply not a cert
            continue

    if not certificates:
        # Try DER: some stores keep raw DER without a PEM envelope.
        if b"-----BEGIN" not in data:
            try:
                certificates.append(x509.load_der_x509_certificate(data))
            except Exception:  # noqa: BLE001
                certificates = []

    now = None
    try:
        from django.utils import timezone

        now = timezone.now()
    except Exception:  # noqa: BLE001 - usable without Django too
        now = None

    for cert in certificates:
        try:
            public_key = cert.public_key()
            algo, key_size, curve = _public_key_detail(public_key)
            subject = _name(cert.subject)
            issuer = _name(cert.issuer)

            expired = None
            not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
            not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
            if now is not None and not_after is not None:
                if not_after.tzinfo is None:
                    from datetime import timezone as _tz

                    not_after = not_after.replace(tzinfo=_tz.utc)
                expired = not_after < now

            details.append(
                CertificateDetail(
                    subject=subject,
                    issuer=issuer,
                    serial=f"{cert.serial_number:x}",
                    not_before=not_before.isoformat() if not_before else "",
                    not_after=not_after.isoformat() if not_after else "",
                    public_key_algorithm=algo,
                    key_size=key_size,
                    curve=curve,
                    signature_algorithm=getattr(
                        cert.signature_algorithm_oid, "_name", None
                    )
                    or str(cert.signature_algorithm_oid),
                    san=_general_names(cert),
                    key_usage=_key_usage(cert),
                    is_ca="CA:TRUE" in (_extension(cert, _BASIC_CONSTRAINTS_OID) or ""),
                    sha256_fingerprint=cert.fingerprint(hashes.SHA256()).hex(),
                    self_signed=subject == issuer,
                    expired=expired,
                )
            )
        except Exception:  # noqa: BLE001 - never let one odd cert fail a scan
            continue

    return details


def looks_like_certificate(data: bytes) -> bool:
    """Cheap pre-check so we only attempt a real parse on plausible files."""
    return b"-----BEGIN CERTIFICATE-----" in data or data[:1] == b"\x30"


def file_fingerprint(data: bytes) -> str:
    """Stable content fingerprint used to correlate artefacts without leaking them."""
    return hashlib.sha256(data).hexdigest()


def is_weak_key(algorithm: str, key_size: int | None) -> bool:
    """Compare a key against NIST SP 800-131A minimums (discovery fact, not a verdict)."""
    if not key_size:
        return False
    minimum = _WEAK_KEY_SIZES.get(algorithm.lower())
    return bool(minimum and key_size < minimum)
