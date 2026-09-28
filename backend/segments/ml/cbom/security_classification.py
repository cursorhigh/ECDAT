"""Authoritative Cryptographic Security and Quantum Threat Classification Layer.

Provides unified, deterministic classification of cryptographic primitives across:
- Classical Security Status (STRONG, WEAK, DEPRECATED, BROKEN, UNKNOWN)
- Quantum Threat Class (SHOR_VULNERABLE, GROVER_REDUCED_MARGIN, NOT_SHOR_VULNERABLE, UNKNOWN)
- PQ Readiness Status (PQC_IMPLEMENTED, QUANTUM_RESILIENT_MARGIN, CLASSICAL_ONLY, UNKNOWN)

Aligns with NIST SP 800-57, FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA),
and NSA CNSA 2.0 guidelines.

Phase B enhancements:
- HMAC-SHA-1 classified as "Legacy - Review" (not Weak, not Retain Strong)
- md5.New / sha1.New inherit their algorithm's classification
- Role-aware hash classification (security vs non-security use)
- RC2 added to classical broken list
- RSA/DSA < 2048 bits explicitly deprecated
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, NamedTuple, Optional


class ClassicalSecurityStatus(str, Enum):
    STRONG = "STRONG"
    WEAK = "WEAK"
    DEPRECATED = "DEPRECATED"
    BROKEN = "BROKEN"
    LEGACY_REVIEW = "LEGACY_REVIEW"
    UNKNOWN = "UNKNOWN"


class QuantumThreatClass(str, Enum):
    SHOR_VULNERABLE = "SHOR_VULNERABLE"
    GROVER_REDUCED_MARGIN = "GROVER_REDUCED_MARGIN"
    NOT_SHOR_VULNERABLE = "NOT_SHOR_VULNERABLE"
    UNKNOWN = "UNKNOWN"


class PQStatus(str, Enum):
    PQC_IMPLEMENTED = "PQC_IMPLEMENTED"
    QUANTUM_RESILIENT_MARGIN = "QUANTUM_RESILIENT_MARGIN"
    CLASSICAL_ONLY = "CLASSICAL_ONLY"
    UNKNOWN = "UNKNOWN"


class CryptoSecurityProfile(NamedTuple):
    classical_status: ClassicalSecurityStatus
    quantum_threat_class: QuantumThreatClass
    pq_status: PQStatus
    is_shor_vulnerable: bool
    risk_key: str
    recommended_action: str
    rationale: str


_SHOR_VULNERABLE_KEYWORDS = (
    "rsa",
    "dsa",
    "dh",
    "diffie-hellman",
    "diffie_hellman",
    "ecc",
    "ecdsa",
    "ecdh",
    "eddsa",
    "ed25519",
    "ed448",
    "x25519",
    "x448",
    "elgamal",
    "p256",
    "p384",
    "p521",
    "secp256r1",
    "secp384r1",
    "secp521r1",
    "secp256k1",
)

_PQC_KEYWORDS = (
    "mlkem",
    "ml-kem",
    "mldsa",
    "ml-dsa",
    "slhdsa",
    "slh-dsa",
    "kyber",
    "dilithium",
    "sphincs",
    "xmss",
    "lms",
    "falcon",
)

_CLASSICAL_BROKEN_KEYWORDS = (
    "des",
    "3des",
    "triple-des",
    "desede",
    "rc4",
    "arcfour",
    "rc2",
    "blowfish",
)

_CLASSICAL_WEAK_HASH_KEYWORDS = (
    "sha1",
    "sha-1",
    "md4",
    "md2",
    "ripemd160",
    "ripemd-160",
)

# HMAC-SHA-1 is NOT collision-broken (HMAC construction protects against it),
# but SHA-1 is deprecated, so classify as Legacy-Review.
_HMAC_SHA1_KEYWORDS = (
    "hmac-sha-1",
    "hmac-sha1",
    "hmacsha1",
    "hmacsha-1",
)


def _clean(s: Optional[str]) -> str:
    return str(s or "").lower().strip()


def _strip_separators(s: str) -> str:
    """Strip hyphens, underscores, spaces for matching."""
    return s.replace("-", "").replace("_", "").replace(" ", "")


def classify_crypto_security(
    algorithm: Optional[str] = None,
    family: Optional[str] = None,
    key_size: Optional[int] = None,
    curve: Optional[str] = None,
    role: Optional[str] = None,
    name: Optional[str] = None,
    source_context: Optional[str] = None,
) -> CryptoSecurityProfile:
    """Authoritatively classify any cryptographic primitive.

    Guarantees:
    - Shor vulnerability is True ONLY for classical public key / discrete log primitives.
    - MD5, SHA-1, DES, 3DES, Blowfish, RC4, RC2 are NEVER marked Shor-vulnerable.
    - AES-256 and SHA-256/384/512 are recognized with proper Grover/collision security margin.
    - HMAC-SHA-1 is classified as Legacy-Review, not Weak or Strong.
    - md5.New, sha1.New inherit the underlying algorithm's classification.
    - Role-aware classification distinguishes security use from non-security checksums.
    """
    algo_clean = _clean(algorithm)
    fam_clean = _clean(family)
    curve_clean = _clean(curve)
    role_clean = _clean(role)
    name_clean = _clean(name)
    ctx_clean = _clean(source_context)

    # Normalize separators for keyword matching
    algo_normalized = _strip_separators(algo_clean)
    combined = f"{algo_clean} {fam_clean} {curve_clean} {name_clean}"
    combined_normalized = _strip_separators(combined)

    # 1. Approved Post-Quantum Cryptography
    if any(k in combined_normalized for k in [_strip_separators(k) for k in _PQC_KEYWORDS]) or fam_clean == "pqc":
        return CryptoSecurityProfile(
            classical_status=ClassicalSecurityStatus.STRONG,
            quantum_threat_class=QuantumThreatClass.NOT_SHOR_VULNERABLE,
            pq_status=PQStatus.PQC_IMPLEMENTED,
            is_shor_vulnerable=False,
            risk_key="pqc",
            recommended_action="Retain standardized post-quantum implementation",
            rationale="Approved post-quantum cryptographic primitive resilient against known classical and quantum attacks.",
        )

    # 2. HMAC-SHA-1 special case: NOT collision-broken, but SHA-1 is deprecated
    # HMAC construction prevents collision attacks, so this is Legacy-Review, not Weak
    if any(k in algo_normalized or k in combined_normalized for k in [_strip_separators(k) for k in _HMAC_SHA1_KEYWORDS]):
        return CryptoSecurityProfile(
            classical_status=ClassicalSecurityStatus.LEGACY_REVIEW,
            quantum_threat_class=QuantumThreatClass.GROVER_REDUCED_MARGIN,
            pq_status=PQStatus.QUANTUM_RESILIENT_MARGIN,
            is_shor_vulnerable=False,
            risk_key="moderate",
            recommended_action="Upgrade to HMAC-SHA-256 / KMAC",
            rationale=(
                "HMAC-SHA-1 is not collision-broken (HMAC construction prevents collision "
                "attacks on the underlying hash), but SHA-1 is deprecated. Upgrade to "
                "HMAC-SHA-256 for compliance with current standards."
            ),
        )

    # 3. Classical Public-Key Cryptography (Shor-Vulnerable)
    # Must check BEFORE broken ciphers since "des" substring might match "ecdsa" etc.
    is_pubkey = (
        fam_clean in ("rsa", "dsa", "dh", "ecc", "asymmetric", "public_key")
        or any(k in combined for k in _SHOR_VULNERABLE_KEYWORDS)
    )
    # Exclude false positives: DES is not Shor-vulnerable
    if is_pubkey and not any(k in algo_normalized for k in ("des", "3des", "desede", "tripledes")):
        is_weak_key = False
        if key_size:
            if fam_clean in ("rsa", "dh", "dsa") and key_size < 2048:
                is_weak_key = True
            elif fam_clean == "ecc" and key_size < 224:
                is_weak_key = True

        classical = ClassicalSecurityStatus.DEPRECATED if is_weak_key else ClassicalSecurityStatus.STRONG

        # Role-aware recommendation
        is_sig = any(w in role_clean or w in name_clean for w in ("sign", "cert", "auth", "verify"))
        is_kex = any(w in role_clean or w in name_clean for w in ("enc", "key", "transport", "exchange", "kem", "agreement"))

        if is_sig and not is_kex:
            rec = "ML-DSA-65 / ML-DSA-87 (FIPS 204)"
            reason = "Classical public-key signatures are vulnerable to Shor's algorithm; migrate to ML-DSA (FIPS 204) per CNSA 2.0."
        elif is_kex:
            rec = "ML-KEM-768 / ML-KEM-1024 (FIPS 203) / Hybrid X25519MLKEM768"
            reason = "Classical key establishment is vulnerable to Shor's algorithm; migrate to ML-KEM (FIPS 203) or hybrid transition."
        elif "ecdsa" in combined or "eddsa" in combined:
            rec = "ML-DSA-65 (FIPS 204) / SLH-DSA"
            reason = "ECDSA signatures are vulnerable to Shor's algorithm; migrate to ML-DSA (FIPS 204)."
        elif "ecdh" in combined or "x25519" in combined or fam_clean == "dh":
            rec = "ML-KEM-768 (Hybrid X25519MLKEM768)"
            reason = "Key exchange is vulnerable to Shor's algorithm; migrate to ML-KEM (FIPS 203) with hybrid transition."
        else:
            rec = "ML-KEM-768 (Key Exchange) / ML-DSA-65 (Signature)"
            reason = "Asymmetric primitive vulnerable to Shor's algorithm; migrate to ML-KEM for key exchange or ML-DSA for signatures."

        return CryptoSecurityProfile(
            classical_status=classical,
            quantum_threat_class=QuantumThreatClass.SHOR_VULNERABLE,
            pq_status=PQStatus.CLASSICAL_ONLY,
            is_shor_vulnerable=True,
            risk_key="vulnerable",
            recommended_action=rec,
            rationale=reason,
        )

    # 4. Classically Broken Ciphers (DES, 3DES, RC4, RC2, Blowfish) -> NOT Shor
    if any(k in combined for k in _CLASSICAL_BROKEN_KEYWORDS):
        # MD5 is handled separately in section 5
        if "md5" not in combined:
            return CryptoSecurityProfile(
                classical_status=ClassicalSecurityStatus.BROKEN if any(k in combined for k in ["des", "rc4", "rc2"]) else ClassicalSecurityStatus.DEPRECATED,
                quantum_threat_class=QuantumThreatClass.NOT_SHOR_VULNERABLE,
                pq_status=PQStatus.CLASSICAL_ONLY,
                is_shor_vulnerable=False,
                risk_key="weak",
                recommended_action="AES-256-GCM / ChaCha20-Poly1305",
                rationale="Classically weak or broken cipher; remediate to modern approved encryption independently of post-quantum timeline.",
            )

    # 5. MD5 — always classically broken, never Shor-vulnerable
    if "md5" in algo_normalized or "md5" in combined_normalized:
        # Role-aware: distinguish password hashing, cert hashing, non-security checksum
        if "password" in role_clean:
            rec = "Argon2id / PBKDF2-HMAC-SHA256"
            reason = "MD5 is cryptographically broken; insecure for password hashing. Migrate to Argon2id or PBKDF2."
        elif "cert" in role_clean or "sign" in role_clean:
            rec = "SHA-256 / SHA-384"
            reason = "MD5 has practical collision attacks; certificates/signatures using MD5 must be re-issued with SHA-256+."
        else:
            rec = "SHA-256 / SHA-3 (or Argon2id for password hashing)"
            reason = "MD5 is cryptographically broken classically; migrate to SHA-256 or SHA-3 for security contexts."

        return CryptoSecurityProfile(
            classical_status=ClassicalSecurityStatus.BROKEN,
            quantum_threat_class=QuantumThreatClass.NOT_SHOR_VULNERABLE,
            pq_status=PQStatus.CLASSICAL_ONLY,
            is_shor_vulnerable=False,
            risk_key="weak",
            recommended_action=rec,
            rationale=reason,
        )

    # 6. Classically Weak Hashes (SHA-1) -> NOT Shor
    if any(k in combined_normalized for k in [_strip_separators(k) for k in _CLASSICAL_WEAK_HASH_KEYWORDS]):
        if "password" in role_clean:
            rec = "Argon2id / PBKDF2-HMAC-SHA256"
            reason = "SHA-1 has practical collision attacks; insecure for password hashing."
        elif "cert" in role_clean or "sign" in role_clean:
            rec = "SHA-256 / SHA-384"
            reason = "SHA-1 in certificate/signature context is vulnerable to collision attacks; re-issue with SHA-256+."
        else:
            rec = "SHA-256 / SHA-3 (or Argon2id for password hashing)"
            reason = "Collision resistance is broken/deprecated classically; migrate to modern hash construction."

        return CryptoSecurityProfile(
            classical_status=ClassicalSecurityStatus.DEPRECATED,
            quantum_threat_class=QuantumThreatClass.NOT_SHOR_VULNERABLE,
            pq_status=PQStatus.CLASSICAL_ONLY,
            is_shor_vulnerable=False,
            risk_key="weak",
            recommended_action=rec,
            rationale=reason,
        )

    # 7. Modern Secure Hashes & MACs (SHA-256, SHA-384, SHA-512, SHA-3, HMAC)
    secure_hash_keywords = ["sha256", "sha384", "sha512", "sha3", "shake",
                            "sha224", "sha2", "blake2"]
    if (fam_clean in ("hash", "mac")
            or any(k in algo_normalized for k in secure_hash_keywords)
            or any(k in combined_normalized for k in secure_hash_keywords + ["hmac"])):
        return CryptoSecurityProfile(
            classical_status=ClassicalSecurityStatus.STRONG,
            quantum_threat_class=QuantumThreatClass.GROVER_REDUCED_MARGIN,
            pq_status=PQStatus.QUANTUM_RESILIENT_MARGIN,
            is_shor_vulnerable=False,
            risk_key="moderate",
            recommended_action="Retain (Strong)",
            rationale="Secure cryptographic hash retaining high classical strength and sufficient quantum collision margin.",
        )

    # 8. Modern Symmetric Encryption (AES, ChaCha20, Camellia, ARIA)
    if (fam_clean in ("aes", "symmetric")
            or any(k in algo_normalized for k in ["aes", "chacha", "camellia", "aria"])):
        bits = key_size or (256 if "256" in combined else (128 if "128" in combined else 256))
        if bits < 256:
            rec = "AES-256-GCM (Upgrade for 128-bit Grover margin)"
            rationale = "Effective 64-bit Grover quantum security bound; evaluate upgrading to AES-256-GCM for critical data."
        else:
            rec = "AES-256-GCM - Retain (Strong)"
            rationale = "AES-256 provides 128 bits of quantum security against Grover's algorithm; retain with approved AEAD mode."

        return CryptoSecurityProfile(
            classical_status=ClassicalSecurityStatus.STRONG,
            quantum_threat_class=QuantumThreatClass.GROVER_REDUCED_MARGIN,
            pq_status=PQStatus.QUANTUM_RESILIENT_MARGIN,
            is_shor_vulnerable=False,
            risk_key="moderate",
            recommended_action=rec,
            rationale=rationale,
        )

    # 9. Unclassified / Unknown Crypto
    return CryptoSecurityProfile(
        classical_status=ClassicalSecurityStatus.UNKNOWN,
        quantum_threat_class=QuantumThreatClass.UNKNOWN,
        pq_status=PQStatus.UNKNOWN,
        is_shor_vulnerable=False,
        risk_key="unknown",
        recommended_action="Reassess after discovery with explicit parameters",
        rationale="Insufficient repository evidence to determine cryptographic parameters.",
    )
