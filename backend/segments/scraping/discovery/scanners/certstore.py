"""Certificate and key-store discovery.

Completes the certificate side of discovery. Certificates are parsed in full;
key material is never exposed. For every artefact the rule is the plan's:

    Detect -> Fingerprint -> Classify -> Reference -> Correlate

Formats covered (plan section 7):

    PEM / CRT / CER   certificate and public key blocks
    DER               raw ASN.1 certificate
    CSR               certificate signing request
    P12 / PFX         PKCS#12 container
    JKS               Java key store

A password-protected store is reported as a container with a fingerprint. Its
contents are not guessed at and no key material is ever returned, logged, or
persisted -- an unencrypted store is decoded only to name what is inside.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from . import x509 as x509_mod

# Extensions that may hold certificate or key material.
CERT_SUFFIXES = {".pem", ".crt", ".cer", ".der", ".csr", ".ca-bundle"}
KEY_SUFFIXES = {".pub", ".key", ".gpg", ".asc"}
STORE_SUFFIXES = {".p12", ".pfx", ".jks", ".keystore", ".truststore", ".bks", ".pkcs12"}

_ALL_SUFFIXES = CERT_SUFFIXES | KEY_SUFFIXES | STORE_SUFFIXES

_PUBKEY_MARKER = re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PUBLIC KEY-----")
_PRIVKEY_MARKER = re.compile(
    rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
)
_CERT_MARKER = re.compile(rb"-----BEGIN (?:TRUSTED )?CERTIFICATE-----")
_CSR_MARKER = re.compile(rb"-----BEGIN (?:NEW |CERTIFICATE )?REQUEST-----")
_PGP_MARKER = re.compile(rb"-----BEGIN PGP (?:PUBLIC|PRIVATE) KEY BLOCK-----")

_JKS_MAGIC = b"\xfe\xed\xfe\xed"
# PKCS#12 is a DER SEQUENCE whose first real tag is often 0x30 0x82.
_PKCS12_MAGIC = b"\x30\x82"


@dataclass
class StoreDetail:
    """A key store that was found, described without its contents."""

    store_type: str = ""
    protected: bool = False
    entries: int = 0
    cert_count: int = 0
    key_count: int = 0
    detail: str = ""

    def as_evidence(self) -> dict:
        return {
            "store_type": self.store_type,
            "password_protected": self.protected,
            "entries": self.entries,
            "certificates": self.cert_count,
            "keys": self.key_count,
            "note": self.detail,
        }


def looks_like_candidate(suffix: str, head: bytes) -> bool:
    """Cheap gate so the scanner only decodes plausible files."""
    suffix = suffix.lower()
    if suffix in _ALL_SUFFIXES:
        return True
    # Trust bundles are frequently stored without a certificate extension.
    if b"-----BEGIN" in head:
        return bool(
            _CERT_MARKER.search(head)
            or _CSR_MARKER.search(head)
            or _PUBKEY_MARKER.search(head)
            or _PRIVKEY_MARKER.search(head)
            or _PGP_MARKER.search(head)
        )
    return False


def inspect_store(data: bytes) -> StoreDetail:
    """Describe a PKCS#12 or JKS container without revealing its secrets.

    An unencrypted PKCS#12 is decoded far enough to count what it holds. A
    password-protected one is reported as a container and fingerprinted, which
    is the honest outcome: the store exists, its type is known, and ECDAT did
    not attempt to open it.
    """
    if data.startswith(_JKS_MAGIC):
        return StoreDetail(
            store_type="jks",
            protected=True,
            detail="Java key store; contents require a password that discovery does not hold.",
        )
    if data.startswith(_PKCS12_MAGIC):
        from cryptography.hazmat.primitives.serialization import pkcs12

        for password in (None, b""):
            try:
                key, certificate, chain = pkcs12.load_key_and_certificates(data, password)
                return StoreDetail(
                    store_type="pkcs12",
                    protected=False,
                    entries=(1 if key else 0) + (1 if certificate else 0) + len(chain or []),
                    cert_count=(1 if certificate else 0) + len(chain or []),
                    key_count=1 if key else 0,
                    detail="Unencrypted PKCS#12 container; only counts were read.",
                )
            except Exception:  # noqa: BLE001 - wrong/empty password is expected
                continue
        return StoreDetail(
            store_type="pkcs12",
            protected=True,
            detail="PKCS#12 container; contents are password protected and were not opened.",
        )
    return StoreDetail()


def _csr_detail(data: bytes) -> dict:
    """Public metadata from a certificate signing request."""
    from cryptography import x509

    try:
        csr = x509.load_pem_x509_csr(data)
    except Exception:  # noqa: BLE001
        return {}
    try:
        public_key = csr.public_key()
    except Exception:  # noqa: BLE001
        return {}
    algo, key_size, curve = x509_mod._public_key_detail(public_key)
    try:
        signature = csr.signature_hash_algorithm.name
    except Exception:  # noqa: BLE001
        signature = ""
    detail = {
        "request_subject": csr.subject.rfc4514_string(),
        "request_is_ca": csr.is_signature_valid,
        "public_key_algorithm": algo,
        "key_size": key_size,
        "signature_algorithm": signature,
    }
    if curve:
        detail["curve"] = curve
    return detail


@dataclass
class Discovery:
    """Everything one file contributed."""

    certificates: list[dict] = field(default_factory=list)
    key_references: list[dict] = field(default_factory=list)
    stores: list[dict] = field(default_factory=list)
    skipped: str = ""


def discover(location: str, data: bytes) -> Discovery:
    """Discover certificates, key references, and stores in one file."""
    result = Discovery()

    # --- certificates ------------------------------------------------------
    if x509_mod.looks_like_certificate(data) or _CERT_MARKER.search(data):
        for detail in x509_mod.load_certificates(data):
            result.certificates.append(
                {
                    "location": location,
                    "kind": "certificate",
                    "family": _family_for(detail.public_key_algorithm),
                    "algorithm": detail.public_key_algorithm,
                    "key_size": detail.key_size,
                    "curve": detail.curve,
                    "library": "X.509",
                    "confidence": 0.99,
                    "evidence": {
                        "type": "x509",
                        "detector": "certificate_store",
                        "value": detail.sha256_fingerprint,
                        **detail.as_evidence(),
                    },
                    "strength": _strength(detail),
                }
            )

    # --- certificate signing requests --------------------------------------
    if _CSR_MARKER.search(data):
        detail = _csr_detail(data)
        if detail:
            result.certificates.append(
                {
                    "location": location,
                    "kind": "certificate",
                    "family": _family_for(detail.get("public_key_algorithm", "")),
                    "algorithm": detail.get("public_key_algorithm", ""),
                    "key_size": detail.get("key_size"),
                    "curve": detail.get("curve", ""),
                    "library": "PKCS#10",
                    "confidence": 0.95,
                    "evidence": {
                        "type": "pkcs10_request",
                        "detector": "certificate_store",
                        "value": hashlib.sha256(data).hexdigest(),
                        **detail,
                    },
                }
            )

    # --- key references and material markers --------------------------------
    # Only a fingerprint and a classification. Never the key.
    if _PRIVKEY_MARKER.search(data) or _PGP_MARKER.search(data):
        family, label = _key_label(data)
        result.key_references.append(
            {
                "location": location,
                "kind": "key_reference",
                "family": family,
                "algorithm": label,
                "library": "private key",
                "confidence": 0.95,
                "evidence": {
                    "type": "key_fingerprint",
                    "detector": "certificate_store",
                    "value": hashlib.sha256(data).hexdigest(),
                    "key_kind": "private",
                    "exposed": False,
                },
                "strength": "private_key_material",
            }
        )
    elif _PUBKEY_MARKER.search(data):
        family, label = _key_label(data)
        result.key_references.append(
            {
                "location": location,
                "kind": "key_reference",
                "family": family,
                "algorithm": label,
                "library": "public key",
                "confidence": 0.95,
                "evidence": {
                    "type": "key_fingerprint",
                    "detector": "certificate_store",
                    "value": hashlib.sha256(data).hexdigest(),
                    "key_kind": "public",
                },
            }
        )

    # --- key stores ---------------------------------------------------------
    store = inspect_store(data)
    if store.store_type:
        result.stores.append(
            {
                "location": location,
                "kind": "key_reference",
                "family": "unknown",
                "algorithm": store.store_type.upper(),
                "library": store.store_type,
                "confidence": 0.9,
                "evidence": {
                    "type": "keystore_container",
                    "detector": "certificate_store",
                    "value": hashlib.sha256(data).hexdigest(),
                    **store.as_evidence(),
                },
            }
        )

    if not (result.certificates or result.key_references or result.stores):
        result.skipped = "no_certificate_or_key_material"
    return result


def _family_for(algorithm: str) -> str:
    return {
        "RSA": "rsa",
        "DSA": "dsa",
        "EC": "ecc",
        "Ed25519": "ecc",
        "Ed448": "ecc",
    }.get(algorithm, "unknown")


def _key_label(data: bytes) -> tuple[str, str]:
    """Classify a key blob without decoding it."""
    from . import keymaterial

    classified = keymaterial.classify_key_blob(data[:4096])
    if classified:
        family, kind = classified
        mapped = {"rsa": "rsa", "dsa": "dsa", "ec": "ecc"}.get(family, "unknown")
        return mapped, family.upper() if mapped != "unknown" else (kind or "key").upper()
    return "unknown", "KEY"


def _strength(detail) -> str | None:
    """Factual observation about a certificate, not a risk verdict."""
    if detail.expired:
        return "expired"
    if detail.self_signed:
        return "self_signed"
    if x509_mod.is_weak_key(detail.public_key_algorithm, detail.key_size):
        return "key_below_minimum"
    return None


def chain_pairs(certificates: list[dict]) -> list[tuple[str, str]]:
    """Issuer/subject pairs, for correlating a leaf to the CA that signed it.

    A pair is only produced when the issuing certificate was itself discovered,
    so a chain link always points at a certificate discovery can also show.
    """
    subjects: dict[str, str] = {}
    for detail in certificates:
        subject = str(detail.get("subject") or "")
        fingerprint = detail.get("sha256_fingerprint")
        if subject and fingerprint:
            subjects.setdefault(subject, fingerprint)

    pairs: list[tuple[str, str]] = []
    for detail in certificates:
        leaf = detail.get("sha256_fingerprint")
        issuer = str(detail.get("issuer") or "")
        subject = str(detail.get("subject") or "")
        if not (leaf and issuer) or issuer == subject:
            continue
        issuer_fingerprint = subjects.get(issuer)
        if issuer_fingerprint and issuer_fingerprint != leaf:
            pairs.append((leaf, issuer_fingerprint))
    return pairs
