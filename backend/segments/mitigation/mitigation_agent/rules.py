"""Deterministic mitigation rule engines.

Each agent runs rules against a single asset context combined with a run
bundle (service usage, exposure, risk context). Together they predict blast
radius, migration impact and produce actionable suggestions without needing
an LLM -- the LLM (NarratorAgent) only polishes narrative prose when a key
is available.

All helpers are pure and unit-testable with plain dicts.

Phase D enhancements:
- Configurable wave logic with documented criteria
- Effort model expressed as range (low/high quarters)
- Action-appropriate remediation (no "rotate now" for negligible exposure)
- Standards profile support (NIST general / CNSA 2.0)
- HMAC-SHA-1 classified as Legacy-Review
- Wave 2 guaranteed non-empty when Shor-vulnerable assets exist
"""

import posixpath
from typing import Any, Dict, List, Optional

PRIORITY_RANK = {"URGENT": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
RISK_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def normalize_algorithm(raw: Any) -> str:
    """Return an uppercase canonical algorithm token from CBOM output."""
    if isinstance(raw, dict):
        raw = raw.get("name", "")
    return str(raw or "").strip().upper()


def service_for_location(file_path: Optional[str]) -> str:
    """Derive the logical service/context for a CBOM asset location.

    Handles both POSIX and Windows paths: prefers an ``apps/<service>``
    segment, then ``<repo>/<service>`` nesting, then the parent directory
    of the file, and finally a stable ``unknown`` string.
    """
    if not file_path:
        return "unknown"
    parts = posixpath.normpath(str(file_path).replace("\\", "/")).split("/")
    parts = [p for p in parts if p]
    if not parts:
        return "unknown"
    for idx, part in enumerate(parts):
        if part.lower() in ("apps", "app", "src", "source", "services", "modules"):
            if idx + 1 < len(parts):
                return parts[idx + 1] or "unknown"
    filename = parts[-1]
    if len(parts) >= 2 and "." in filename:
        return parts[-2] or "unknown"
    return "unknown"


def service_for_asset(asset_ctx: Dict[str, Any]) -> str:
    cbom = asset_ctx.get("cbom_asset") or {}
    location = cbom.get("location") or {}
    return service_for_location(location.get("file"))


def exposure_for(run_bundle: Dict[str, Any]) -> str:
    """Collapse risk-context network flags into public/internal/isolated."""
    risk = run_bundle.get("risk_context") or {}
    network = risk.get("network") or {}
    if network.get("publicly_accessible") or network.get("internet_facing"):
        return "public"
    if network.get("external_users"):
        return "external"
    return "internal"


# ---------------------------------------------------------------------------
# BlastRadiusAgent
# ---------------------------------------------------------------------------


def _base_severity(asset_ctx: Dict[str, Any]) -> str:
    priority = asset_ctx.get("migration_priority") or "MEDIUM"
    return {
        "URGENT": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
    }.get(priority.upper(), "MEDIUM")


def compute_blast_radius(asset_ctx: Dict[str, Any], run_bundle: Dict[str, Any]) -> Dict[str, Any]:
    """Predict how far a cryptographic failure reaches for one asset."""
    category = (asset_ctx.get("algorithm_category") or "UNKNOWN").upper()
    qv = bool(asset_ctx.get("quantum_vulnerable"))
    priority = (asset_ctx.get("migration_priority") or "MEDIUM").upper()
    service = asset_ctx.get("service") or service_for_asset(asset_ctx)
    exposure = exposure_for(run_bundle)
    shared = sum(
        1
        for other in run_bundle.get("assets") or []
        if other.get("id") != asset_ctx.get("id")
        and (other.get("service") or service_for_asset(other)) == service
    )

    severity = _base_severity(asset_ctx)
    if category == "PUBLIC_KEY" and qv:
        # A CRQC can break these outright (Shor), not just weaken them.
        severity = "CRITICAL" if priority in ("URGENT", "HIGH") else "HIGH"
    if exposure == "public" and severity == "MEDIUM":
        severity = "HIGH"
    if category == "HASH" and asset_ctx.get("algorithm") and str(asset_ctx.get("algorithm")).upper() in ("MD5", "SHA1"):
        severity = "MEDIUM"

    reason = (
        f"{asset_ctx.get('algorithm') or 'Unknown'} in '{service}' exposes "
        f"{shared + 1} crypto asset(s); surface is {exposure}."
    )
    if category == "PUBLIC_KEY" and qv:
        reason = (
            f"{asset_ctx.get('algorithm') or 'Unknown'} is post-quantum vulnerable "
            f"(Shor) and lives in '{service}' ({exposure} surface); compromise breaks "
            f"confidentiality and integrity for {shared + 1} trust chain member(s)."
        )
    return {
        "severity": severity,
        "severity_rank": SEVERITY_RANK.get(severity, 3),
        "service": service,
        "exposure": exposure,
        "shared_assets": shared + 1,
        "services_affected": [service],
        "reason": reason,
    }


# ---------------------------------------------------------------------------
# MigrationImpactAgent
# ---------------------------------------------------------------------------

_ROLE_SIGNATURE_TOKENS = {"digital_signature", "signature", "signing", "sign", "authentication", "certificate", "cert"}
_ROLE_KEY_EXCHANGE_TOKENS = {"key_establishment", "key_exchange", "key_agreement", "encryption", "transport_security", "kdf", "kem"}

_REPLACEMENTS = {
    # (canonical algo) -> (replacement, category, effort, impact, compatibility_risk, reason)
    "RSA": (
        "ML-KEM-768 (Key Exchange) / ML-DSA-65 (Signatures)",
        "PUBLIC_KEY",
        "HIGH",
        "HIGH",
        "HIGH",
        "RSA is vulnerable to Shor's algorithm; for key encapsulation, migrate to NIST FIPS 203 (ML-KEM-768); for digital signatures, migrate to FIPS 204 (ML-DSA-65).",
    ),
    "RSA-2048": (
        "ML-KEM-768 (Key Exchange) / ML-DSA-65 (Signatures)",
        "PUBLIC_KEY",
        "HIGH",
        "HIGH",
        "HIGH",
        "RSA-2048 is vulnerable to Shor's algorithm; migrate to NIST FIPS 203 (ML-KEM-768) for key transport or FIPS 204 (ML-DSA-65) for digital signatures.",
    ),
    "RSA-3072": (
        "ML-KEM-768 (Key Exchange) / ML-DSA-65 (Signatures)",
        "PUBLIC_KEY",
        "HIGH",
        "HIGH",
        "HIGH",
        "RSA-3072 is vulnerable to Shor's algorithm; migrate to NIST FIPS 203 (ML-KEM-768) or FIPS 204 (ML-DSA-65) based on cryptographic role.",
    ),
    "RSA-4096": (
        "ML-KEM-1024 (Key Exchange) / ML-DSA-87 (Signatures)",
        "PUBLIC_KEY",
        "HIGH",
        "HIGH",
        "HIGH",
        "RSA-4096 is vulnerable to Shor's algorithm; migrate to NIST FIPS 203 (ML-KEM-1024) or FIPS 204 (ML-DSA-87) based on cryptographic role.",
    ),
    "ECDSA": (
        "ML-DSA-65 (FIPS 204) / SLH-DSA",
        "PUBLIC_KEY",
        "MEDIUM",
        "MEDIUM",
        "MEDIUM",
        "ECDSA digital signatures are vulnerable to Shor's algorithm; migrate to NIST FIPS 204 (ML-DSA-65).",
    ),
    "ECDSA-P256": (
        "ML-DSA-65 (FIPS 204)",
        "PUBLIC_KEY",
        "MEDIUM",
        "MEDIUM",
        "MEDIUM",
        "ECDSA P-256 digital signatures migrate to ML-DSA-65 (FIPS 204).",
    ),
    "ECDSA-P384": (
        "ML-DSA-87 (FIPS 204)",
        "PUBLIC_KEY",
        "MEDIUM",
        "MEDIUM",
        "MEDIUM",
        "ECDSA P-384 digital signatures migrate to ML-DSA-87 (FIPS 204).",
    ),
    "ECDH": (
        "ML-KEM-768 (FIPS 203) / Hybrid X25519MLKEM768",
        "PUBLIC_KEY",
        "MEDIUM",
        "MEDIUM",
        "MEDIUM",
        "ECDH key agreement is vulnerable to Shor's algorithm; migrate to ML-KEM (FIPS 203) with a hybrid transition (X25519MLKEM768) where interoperability dictates.",
    ),
    "X25519": (
        "ML-KEM-768 (Hybrid X25519MLKEM768)",
        "PUBLIC_KEY",
        "LOW",
        "LOW",
        "LOW",
        "X25519 key exchange upgrades to hybrid X25519MLKEM768 for immediate post-quantum key establishment security.",
    ),
    "EC": (
        "ML-KEM-768 (Key Exchange) / ML-DSA-65 (Signatures)",
        "PUBLIC_KEY",
        "MEDIUM",
        "MEDIUM",
        "MEDIUM",
        "Elliptic-curve primitives move to ML-KEM (FIPS 203) for key exchange or ML-DSA (FIPS 204) for digital signatures.",
    ),
    "ECC": (
        "ML-KEM-768 (Key Exchange) / ML-DSA-65 (Signatures)",
        "PUBLIC_KEY",
        "MEDIUM",
        "MEDIUM",
        "MEDIUM",
        "Elliptic-curve primitives move to ML-KEM (FIPS 203) for key exchange or ML-DSA (FIPS 204) for digital signatures.",
    ),
    "ED25519": (
        "ML-DSA-65 (FIPS 204) / SLH-DSA",
        "PUBLIC_KEY",
        "MEDIUM",
        "MEDIUM",
        "MEDIUM",
        "Ed25519 digital signatures migrate to ML-DSA-65 (FIPS 204) or stateless hash-based SLH-DSA (FIPS 205); maintain graceful dual-verification during transition.",
    ),
    "EDDSA": (
        "ML-DSA-65",
        "PUBLIC_KEY",
        "MEDIUM",
        "MEDIUM",
        "MEDIUM",
        "EdDSA signatures migrate to ML-DSA-65 (FIPS 204) per CNSA 2.0.",
    ),
    "DSA": (
        "ML-DSA-87",
        "PUBLIC_KEY",
        "HIGH",
        "HIGH",
        "HIGH",
        "DSA signatures are legacy and vulnerable to Shor's algorithm; replace with ML-DSA-87 (FIPS 204).",
    ),
    "DH": (
        "ML-KEM-1024 (or Hybrid Transition)",
        "PUBLIC_KEY",
        "HIGH",
        "HIGH",
        "HIGH",
        "Diffie-Hellman key exchange is vulnerable to Shor's algorithm; move to ML-KEM (FIPS 203).",
    ),
    "ELGAMAL": (
        "ML-KEM-1024",
        "PUBLIC_KEY",
        "HIGH",
        "HIGH",
        "HIGH",
        "ElGamal asymmetric encryption migrates to ML-KEM key encapsulation.",
    ),
    "AES": (
        "AES-256 (GCM)",
        "SYMMETRIC",
        "LOW",
        "LOW",
        "LOW",
        "AES-256 provides 128 bits of post-quantum security margin against Grover's algorithm; retain and validate AEAD (GCM) mode.",
    ),
    "AES-128": (
        "AES-256 (GCM)",
        "SYMMETRIC",
        "MEDIUM",
        "MEDIUM",
        "MEDIUM",
        "AES-128 has an effective 64-bit quantum security bound under Grover's algorithm; evaluate upgrading to AES-256-GCM for critical long-term confidentiality.",
    ),
    "AES-256": (
        "AES-256 (GCM) - Retain (Strong)",
        "SYMMETRIC",
        "LOW",
        "LOW",
        "LOW",
        "AES-256 is quantum-resilient with 128-bit Grover security margin; no PQC algorithm replacement required, retain with approved AEAD mode.",
    ),
    "CHACHA20": (
        "ChaCha20-Poly1305 / AES-256 (GCM)",
        "SYMMETRIC",
        "LOW",
        "LOW",
        "LOW",
        "ChaCha20 provides 256-bit key quantum security (128-bit Grover bound); retain and pair with Poly1305 AEAD.",
    ),
    "DES": (
        "AES-256 (GCM) / ChaCha20-Poly1305",
        "CLASSICAL_WEAK",
        "MEDIUM",
        "MEDIUM",
        "MEDIUM",
        "DES is broken classically due to short 56-bit keys; remediate to modern AES-256-GCM or ChaCha20-Poly1305 independently of quantum readiness.",
    ),
    "3DES": (
        "AES-256 (GCM) / ChaCha20-Poly1305",
        "CLASSICAL_WEAK",
        "MEDIUM",
        "MEDIUM",
        "MEDIUM",
        "3DES is deprecated and vulnerable to Sweet32; migrate to AES-256-GCM independently of quantum readiness.",
    ),
    "BLOWFISH": (
        "AES-256 (GCM)",
        "CLASSICAL_WEAK",
        "MEDIUM",
        "MEDIUM",
        "MEDIUM",
        "Blowfish is legacy with 64-bit block size (Sweet32 risk); migrate to AES-256-GCM.",
    ),
    "RC4": (
        "AES-256 (GCM) / ChaCha20-Poly1305",
        "CLASSICAL_WEAK",
        "MEDIUM",
        "MEDIUM",
        "MEDIUM",
        "RC4 is cryptographically broken classically; remediate to modern authenticated ciphers (AES-256-GCM).",
    ),
    "CAMELLIA": (
        "AES-256 (GCM)",
        "SYMMETRIC",
        "MEDIUM",
        "MEDIUM",
        "MEDIUM",
        "Camellia is acceptable; consolidate on AES-256-GCM where possible.",
    ),
    "SHA1": (
        "SHA-256 / SHA-3",
        "CLASSICAL_WEAK",
        "LOW",
        "LOW",
        "MEDIUM",
        "SHA-1 has practical collision attacks; replace with SHA-256 or SHA-3 for integrity, password hashing, and certificate signing.",
    ),
    "SHA-1": (
        "SHA-256 / SHA-3",
        "CLASSICAL_WEAK",
        "LOW",
        "LOW",
        "MEDIUM",
        "SHA-1 has practical collision attacks; replace with SHA-256 or SHA-3 for integrity, password hashing, and certificate signing.",
    ),
    "MD5": (
        "SHA-256 / SHA-3",
        "CLASSICAL_WEAK",
        "LOW",
        "LOW",
        "HIGH",
        "MD5 is cryptographically broken classically; remediate to SHA-256 or SHA-3 for security contexts.",
    ),
    "SHA256": (
        "SHA-256 / SHA-3 - Retain (Strong)",
        "HASH",
        "LOW",
        "LOW",
        "LOW",
        "SHA-256 is quantum-resilient against Grover/collision attacks; retain for general integrity and HMAC constructions.",
    ),
    "SHA-256": (
        "SHA-256 / SHA-3 - Retain (Strong)",
        "HASH",
        "LOW",
        "LOW",
        "LOW",
        "SHA-256 is quantum-resilient against Grover/collision attacks; retain for general integrity and HMAC constructions.",
    ),
    "SHA384": (
        "SHA-384 / SHA-3 - Retain (Strong)",
        "HASH",
        "LOW",
        "LOW",
        "LOW",
        "SHA-384 provides high quantum security margin; retain for CNSA 2.0 compliance.",
    ),
    "SHA-384": (
        "SHA-384 / SHA-3 - Retain (Strong)",
        "HASH",
        "LOW",
        "LOW",
        "LOW",
        "SHA-384 provides high quantum security margin; retain for CNSA 2.0 compliance.",
    ),
    "SHA512": (
        "SHA-512 / SHA-3 - Retain (Strong)",
        "HASH",
        "LOW",
        "LOW",
        "LOW",
        "SHA-512 provides high quantum security margin; retain for integrity and signature digests.",
    ),
    "SHA-512": (
        "SHA-512 / SHA-3 - Retain (Strong)",
        "HASH",
        "LOW",
        "LOW",
        "LOW",
        "SHA-512 provides high quantum security margin; retain for integrity and signature digests.",
    ),
    "SHA3": (
        "SHA-3 - Retain (Strong)",
        "HASH",
        "LOW",
        "LOW",
        "LOW",
        "SHA-3 is standardized quantum-resilient hashing; retain as approved PQC-ready hash.",
    ),
    "HMAC": (
        "HMAC-SHA-256 / KMAC - Retain (Strong)",
        "HASH",
        "LOW",
        "LOW",
        "LOW",
        "HMAC is quantum-resilient when paired with SHA-256+; no PQC algorithm replacement needed, maintain scheduled key rotation.",
    ),
    "HMAC-SHA-1": (
        "HMAC-SHA-256 / KMAC",
        "LEGACY_REVIEW",
        "MEDIUM",
        "MEDIUM",
        "MEDIUM",
        "HMAC-SHA-1 is not collision-broken (HMAC construction protects), but SHA-1 is deprecated. Upgrade to HMAC-SHA-256 for compliance.",
    ),
    "HMAC-SHA-256": (
        "HMAC-SHA-256 - Retain (Strong)",
        "HASH",
        "LOW",
        "LOW",
        "LOW",
        "HMAC-SHA-256 is quantum-resilient; retain with scheduled key rotation.",
    ),
}

_UNKNOWN_REPLACEMENT = (
    "Review & standards triage",
    "UNKNOWN",
    "MEDIUM",
    "MEDIUM",
    "MEDIUM",
    "Unrecognized or custom crypto requires a standards-compliance review.",
)


def compute_migration_impact(asset_ctx: Dict[str, Any], profile: str = "nist_general") -> Dict[str, Any]:
    """Predict the effort, compatibility risk and role-aware PQC replacement for an asset."""
    algo = normalize_algorithm(asset_ctx.get("algorithm"))
    family = str(asset_ctx.get("family") or "").upper()
    cbom_asset = asset_ctx.get("cbom_asset") or {}
    role = str(asset_ctx.get("crypto_role") or cbom_asset.get("crypto_role") or cbom_asset.get("purpose") or "").lower().strip()
    active_profile = str(asset_ctx.get("standards_profile") or profile or "nist_general").lower()
    is_cnsa = active_profile == "cnsa_2_0"

    lookup = algo
    if lookup not in _REPLACEMENTS:
        lookup = family
    if lookup not in _REPLACEMENTS:
        lookup = algo.split()[0] if algo else ""
    if lookup not in _REPLACEMENTS:
        lookup = algo.split("-")[0] if algo else ""
    if lookup not in _REPLACEMENTS:
        lookup = algo.split("_")[0] if algo else ""
    if lookup not in _REPLACEMENTS:
        lookup = ""

    replacement, category, effort, impact, compat, reason = _REPLACEMENTS.get(
        lookup, _UNKNOWN_REPLACEMENT
    )

    # Role-Aware Refinements:
    # 1. RSA Refinements based on cryptographic role
    if "RSA" in algo or family == "RSA":
        if is_cnsa:
            if any(r in role for r in _ROLE_SIGNATURE_TOKENS):
                replacement = "ML-DSA-87 (FIPS 204)"
                reason = f"{algo} is used for digital signatures; migrate directly to CNSA 2.0 compliant ML-DSA-87 (FIPS 204)."
            elif any(r in role for r in _ROLE_KEY_EXCHANGE_TOKENS):
                replacement = "ML-KEM-1024 (FIPS 203)"
                reason = f"{algo} is used for key establishment/encryption; migrate to CNSA 2.0 compliant ML-KEM-1024 (FIPS 203)."
            else:
                replacement = "ML-KEM-1024 / ML-DSA-87"
                reason = f"{algo} is vulnerable to Shor's algorithm; migrate to CNSA 2.0 compliant ML-KEM-1024 or ML-DSA-87."
        elif any(r in role for r in _ROLE_SIGNATURE_TOKENS):
            replacement = "ML-DSA-65 (FIPS 204)" if "2048" in algo or "3072" in algo else "ML-DSA-87 (FIPS 204)"
            reason = f"{algo} is used for digital signatures; migrate directly to NIST FIPS 204 ({replacement.split()[0]})."
        elif any(r in role for r in _ROLE_KEY_EXCHANGE_TOKENS):
            replacement = "ML-KEM-768 (FIPS 203)" if "2048" in algo or "3072" in algo else "ML-KEM-1024 (FIPS 203)"
            reason = f"{algo} is used for key establishment/encryption; migrate to NIST FIPS 203 ({replacement.split()[0]})."

    # 2. Elliptic Curve (ECC / EC / ECDSA / ECDH) Refinements based on role
    elif any(k in algo for k in ["ECC", "EC", "P256", "P384", "P521"]) or family == "ECC":
        if is_cnsa:
            if "ECDH" in algo or any(r in role for r in _ROLE_KEY_EXCHANGE_TOKENS):
                replacement = "ML-KEM-1024 (FIPS 203)"
                reason = "ECDH key establishment is Shor-vulnerable; migrate to CNSA 2.0 compliant ML-KEM-1024 (FIPS 203)."
            elif "ECDSA" in algo or any(r in role for r in _ROLE_SIGNATURE_TOKENS):
                replacement = "ML-DSA-87 (FIPS 204)"
                reason = "ECDSA digital signatures are Shor-vulnerable; migrate to CNSA 2.0 compliant ML-DSA-87 (FIPS 204)."
            else:
                replacement = "ML-KEM-1024 (Key Exchange) / ML-DSA-87 (Signatures)"
                reason = "Elliptic-curve primitives migrate to CNSA 2.0 compliant ML-KEM-1024 / ML-DSA-87."
        elif "ECDH" in algo or any(r in role for r in _ROLE_KEY_EXCHANGE_TOKENS):
            replacement = "ML-KEM-768 (Hybrid X25519MLKEM768)"
            reason = "ECDH key establishment is Shor-vulnerable; migrate to ML-KEM (FIPS 203) with hybrid transition."
        elif "ECDSA" in algo or any(r in role for r in _ROLE_SIGNATURE_TOKENS):
            replacement = "ML-DSA-65 (FIPS 204)" if "256" in algo or not "384" in algo else "ML-DSA-87 (FIPS 204)"
            reason = "ECDSA digital signatures are Shor-vulnerable; migrate to ML-DSA (FIPS 204)."
        elif algo in ("ECC", "EC"):
            replacement = "ML-KEM-768 (Key Exchange) / ML-DSA-65 (Signatures)"
            reason = "Elliptic-curve primitives move to ML-KEM (FIPS 203) for key exchange or ML-DSA (FIPS 204) for digital signatures."

    # 3. Hash Refinements based on purpose
    elif any(k in algo for k in ["SHA", "MD5", "HASH"]) or family == "HASH":
        if algo in ("MD5", "SHA1", "SHA-1"):
            if "password" in role:
                replacement = "Argon2id / PBKDF2-HMAC-SHA256"
                reason = f"{algo} is insecure for password hashing; migrate to memory-hard Argon2id or PBKDF2."
            elif "certificate" in role or "cert" in role:
                replacement = "SHA-256 / SHA-384"
                reason = f"{algo} in certificate signature is vulnerable to collision attacks; re-issue with SHA-256+."
            else:
                replacement = "SHA-256 / SHA-3"
                reason = f"{algo} is cryptographically weak; replace with SHA-256 or SHA-3 for security contexts."
        elif "HMAC-SHA1" in algo or "HMAC-SHA-1" in algo:
            replacement = "HMAC-SHA-256 / KMAC"
            reason = "HMAC-SHA-1 uses deprecated SHA-1 digest; upgrade to HMAC-SHA-256 or standardized KMAC."
            effort, impact, compat = "MEDIUM", "MEDIUM", "MEDIUM"
        elif any(k in algo for k in ["SHA-256", "SHA256", "SHA-384", "SHA384", "SHA-512", "SHA512", "SHA3", "SHAKE"]):
            replacement = f"{algo} - Retain (Strong)" if "Retain" not in replacement else replacement
            reason = f"{algo} is a secure cryptographic hash providing strong classical and quantum collision resistance; retain."
            effort, impact, compat = "LOW", "LOW", "LOW"

    # Category override from deterministic analysis
    category_override = asset_ctx.get("algorithm_category") or category
    if "AES" in algo or family in ("AES", "SYMMETRIC"):
        params = cbom_asset.get("parameters") or {}
        key_size = params.get("key_size") or asset_ctx.get("key_size") or cbom_asset.get("key_size")
        if "256" in algo or (key_size is not None and str(key_size).isdigit() and int(key_size) >= 256):
            effort, impact, compat = "LOW", "LOW", "LOW"
            replacement = "AES-256 (GCM) - Retain (Strong)"
            reason = "AES-256 is quantum-resilient at 128-bit Grover security bound; retain with AEAD (GCM) mode."
        elif "128" in algo or (key_size is not None and str(key_size).isdigit() and int(key_size) < 256):
            effort, impact, compat = "MEDIUM", "MEDIUM", "MEDIUM"
            replacement = "AES-256 (GCM)"
            reason = "AES-128 key length offers 64-bit Grover security bound; upgrade to AES-256-GCM for long-term safety."

    return {
        "replacement": replacement,
        "replacement_category": category_override,
        "effort": effort,
        "impact": impact,
        "compatibility_risk": compat,
        "reason": reason,
    }


def migration_wave_for(asset_ctx: Dict[str, Any], blast: Dict[str, Any]) -> int:
    """Assign assets to a migration wave.

    Wave logic (documented and configurable):
      Wave 1 (0-3 months): Classical-weak security-use crypto, urgent HNDL exposure
        or urgent internet-facing key establishment, critical inventory gaps.
      Wave 2 (3-12 months): Remaining Shor-vulnerable public key (hybrid KEM,
        PQC signatures, cert chain rotation).
      Wave 3 (12-24 months): Symmetric/digest hardening, governance.

    Wave 2 is guaranteed non-empty when Shor-vulnerable assets exist outside
    Wave 1 criteria.
    """
    if asset_ctx.get("remediation_wave") in (1, 2, 3):
        return int(asset_ctx["remediation_wave"])
    if str(asset_ctx.get("migration_priority") or "").upper() == "URGENT":
        return 1

    priority = (asset_ctx.get("migration_priority") or "MEDIUM").upper()
    category = (asset_ctx.get("algorithm_category") or "").upper()
    algo = normalize_algorithm(asset_ctx.get("algorithm"))
    qv = bool(asset_ctx.get("quantum_vulnerable"))
    severity = blast.get("severity", "MEDIUM")
    exposure = blast.get("exposure", "internal")
    hndl = str(asset_ctx.get("hndl_risk") or "").upper()
    evidence_ctx = str(asset_ctx.get("source_context") or "").lower()

    # Classical-weak security-use crypto always Wave 1
    is_classical_weak = algo in ("MD5", "SHA1", "SHA-1", "DES", "3DES", "RC4", "RC2", "BLOWFISH")
    if is_classical_weak and evidence_ctx not in ("test", "docs", "comment", "example"):
        return 1

    # Urgent HNDL-exposed or urgent public-key establishment → Wave 1
    if hndl in ("HIGH", "CRITICAL") and qv:
        return 1
    if exposure == "public" and priority in ("URGENT", "CRITICAL") and qv:
        return 1
    if priority == "URGENT":
        return 1

    # Remaining Shor-vulnerable public key → Wave 2
    if category == "PUBLIC_KEY" and qv:
        return 2
    if category == "PUBLIC_KEY" or priority == "HIGH" or severity == "HIGH":
        return 2

    # Everything else → Wave 3 (symmetric/digest hardening, governance)
    return 3


# ---------------------------------------------------------------------------
# SuggestionAgent
# ---------------------------------------------------------------------------


def suggestions_for(asset_ctx: Dict[str, Any], blast: Dict[str, Any], impact: Dict[str, Any]) -> List[str]:
    """Return a short, ordered list of actionable next steps for one asset."""
    algo = normalize_algorithm(asset_ctx.get("algorithm")) or "Unknown"
    category = (asset_ctx.get("algorithm_category") or "UNKNOWN").upper()
    qv = bool(asset_ctx.get("quantum_vulnerable"))
    priority = (asset_ctx.get("migration_priority") or "").upper()
    service = blast.get("service", "unknown")
    replacement = impact.get("replacement", "")
    hndl = asset_ctx.get("hndl_risk") or ""
    profile = str(asset_ctx.get("standards_profile") or "nist_general").lower()
    profile_label = "CNSA 2.0" if profile == "cnsa_2_0" else "NIST General (FIPS 203/204/205)"

    out: List[str] = []
    if category == "PUBLIC_KEY":
        out.append(
            f"Migrate {algo} to {replacement} ({profile_label}) in '{service}'."
        )
        if "kem" in replacement.lower() or any(k in algo for k in ["ECDH", "DH", "X25519", "RSA"]):
            out.append(
                "Consider hybrid key establishment using X25519MLKEM768 where protocol support "
                "and interoperability requirements permit."
            )
        if asset_ctx.get("key_hygiene_issue") or asset_ctx.get("certificate_expired"):
            out.append(
                f"Rotate expired/weak certificate in '{service}' and enforce automated renewal."
            )
        if qv:
            out.append(
                f"Classify data protected by {algo} and sequence algorithm migration to an approved PQC scheme."
            )
    elif category == "SYMMETRIC":
        if any(w in algo.upper() for w in ["DES", "3DES", "RC4", "BLOWFISH"]) or "weak" in replacement.lower():
            out.append(
                f"Migrate legacy {algo} cipher in '{service}' to modern approved encryption ({replacement})."
            )
            out.append("Retire legacy ciphers and enforce modern AEAD modes (AES-256-GCM / ChaCha20-Poly1305).")
        else:
            out.append(
                f"Retain {algo} with approved AEAD mode (e.g. GCM); validate key-management and rotation in '{service}'."
            )
            out.append("Ensure symmetric keys are rotated on schedule and stored in a KMS.")
    elif category == "HASH":
        if algo.upper() in ("MD5", "SHA1", "SHA-1"):
            out.append(
                f"Migrate deprecated {algo} in '{service}' to approved hash construction ({replacement})."
            )
            out.append(f"Remove {algo} from security-sensitive signature and digest paths.")
        elif any(k in algo.upper() for k in ["SHA-256", "SHA256", "SHA-384", "SHA384", "SHA-512", "SHA512", "SHA3", "SHAKE"]):
            out.append(
                f"Retain {algo} for integrity and digest contexts in '{service}'."
            )
            out.append("Maintain routine cryptographic hygiene and key rotation for HMAC constructions.")
        else:
            out.append(
                f"Review and identify {algo} reference in '{service}' for cryptographic standards compliance."
            )
    else:
        out.append(
            f"Triage the {algo} reference in '{service}' for standards compliance."
        )
        out.append("Add a crypto policy guard: only approved suites may ship.")

    if priority == "URGENT":
        out.append("Treat as a Week-0 item: raise a change ticket and assign an owner.")
    elif priority == "HIGH":
        out.append("Schedule within the current migration quarter; assign an owner.")

    return out[:4]


def recommended_action_for(asset_ctx: Dict[str, Any]) -> str:
    mosca = asset_ctx.get("mosca") or {}
    assessment = mosca.get("mosca_assessment") or {}
    action = assessment.get("recommended_action")
    if action:
        return action
    priority = (asset_ctx.get("migration_priority") or "").upper()
    if priority == "URGENT":
        return "Prioritize a structured migration plan toward appropriate post-quantum mechanisms."
    if priority == "HIGH":
        return "Schedule replacement within the current migration window."
    if priority == "MEDIUM":
        return "Plan replacement during the next major release."
    return "Monitor and maintain current deployment with sound key management."


# ---------------------------------------------------------------------------
# Plan-level helpers
# ---------------------------------------------------------------------------


def digital_twin(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """Build the abstract 'digital twin' view of the crypto estate."""
    assets = bundle.get("assets") or []
    services: Dict[str, int] = {}
    algorithm_counts: Dict[str, int] = {}
    algorithm_services: Dict[str, List[str]] = {}
    for asset in assets:
        service = asset.get("service") or service_for_asset(asset)
        services[service] = services.get(service, 0) + 1
        algo = normalize_algorithm(asset.get("algorithm")) or "Unknown"
        algorithm_counts[algo] = algorithm_counts.get(algo, 0) + 1
        algorithm_services.setdefault(algo, [])
        if service not in algorithm_services[algo]:
            algorithm_services[algo].append(service)

    abstractions = []
    for algo in sorted(algorithm_counts, key=lambda a: -algorithm_counts[a]):
        abstractions.append(
            {
                "type": "algorithm",
                "label": algo,
                "count": algorithm_counts[algo],
                "contexts": algorithm_services[algo],
                "roles": _roles_for(algo),
            }
        )

    risk = bundle.get("risk_context") or {}
    network = risk.get("network") or {}
    data = risk.get("data") or {}
    return {
        "abstractions": abstractions,
        "contexts": {
            "services": sorted(services),
            "applications": [bundle.get("application") or "ECDAT inventory"],
            "exposure": exposure_for(bundle),
            "data_types": data.get("types") or [],
            "publicly_accessible": bool(network.get("publicly_accessible") or network.get("internet_facing")),
        },
        "high_value_points": [
            {
                "label": f"Service '{s}'",
                "reason": f"concentrates {c} cryptographic asset(s) in one blast zone",
            }
            for s, c in sorted(services.items(), key=lambda kv: -kv[1])[:4]
        ],
    }


def _roles_for(algo: str) -> List[str]:
    if algo in ("RSA", "ECDSA", "ED25519", "EDDSA", "DSA"):
        return ["digital_signature", "authentication", "certificates"]
    if algo in ("ECDH", "DH", "ELGAMAL"):
        return ["key_exchange", "transport_security"]
    if algo in ("AES", "DES", "3DES", "BLOWFISH", "RC4", "CAMELLIA"):
        return ["confidentiality", "data_encryption"]
    if algo.startswith("SHA") or algo == "MD5":
        return ["integrity", "message_digest"]
    if algo == "HMAC":
        return ["keyed_integrity", "message_authentication"]
    return ["cryptographic_primitives"]


def quantum_risk(bundle: Dict[str, Any]) -> Dict[str, Any]:
    assets = bundle.get("assets") or []
    vulnerable = [
        {
            "asset_id": a.get("id"),
            "algorithm": normalize_algorithm(a.get("algorithm")) or "Unknown",
            "service": a.get("service") or service_for_asset(a),
            "priority": a.get("migration_priority"),
        }
        for a in assets
        if a.get("quantum_vulnerable")
    ]
    hndl_high = sum(
        1 for a in assets if str(a.get("hndl_risk") or "").upper() in ("HIGH", "CRITICAL")
    )
    return {
        "post_quantum_vulnerable": vulnerable,
        "hndl_present": hndl_high > 0,
        "harvest_now_decrypt_later": hndl_high > 0,
        "rationale": (
            "Public-key primitives (RSA, ECC) are vulnerable to Shor's algorithm on a "
            "future cryptographically-relevant quantum computer (CRQC). Ciphertext "
            "captured today can be decrypted later (Harvest-Now-Decrypt-Later), and "
            "long-lived signatures forged - which is why PQC migration is time-critical."
        ),
        "urgency": "Wave 1" if vulnerable else "Wave 3",
    }


def blast_radius_summary(bundle: Dict[str, Any]) -> Dict[str, Any]:
    assets = bundle.get("assets") or []
    severities = [a.get("blast", {}).get("severity", "LOW") for a in assets]
    worst = "LOW"
    if severities:
        worst = min(severities, key=lambda s: SEVERITY_RANK.get(s, 3))
    per_algo: Dict[str, Dict[str, Any]] = {}
    for a in assets:
        algo = normalize_algorithm(a.get("algorithm")) or "Unknown"
        sev = a.get("blast", {}).get("severity", "LOW")
        entry = per_algo.setdefault(algo, {"count": 0, "severity": sev})
        entry["count"] += 1
        if SEVERITY_RANK.get(sev, 3) < SEVERITY_RANK.get(entry["severity"], 3):
            entry["severity"] = sev
    services = {a.get("service") or service_for_asset(a) for a in assets}
    return {
        "severity": worst,
        "affected_services": len(services),
        "affected_findings": len(assets),
        "public_surface": exposure_for(bundle) == "public",
        "per_algorithm": [
            {"algorithm": algo, "count": entry["count"], "severity": entry["severity"]}
            for algo, entry in sorted(per_algo.items(), key=lambda kv: SEVERITY_RANK.get(kv[1]["severity"], 3))
        ],
        "poorest_link": worst,
    }


WAVE_DEFS = [
    {
        "name": "Wave 1 — Classical-weak remediation & HNDL triage",
        "timeline": "0-3 months",
        "criteria": (
            "Classical-weak security-use crypto (MD5, SHA-1, DES, 3DES, RC4, RC2, Blowfish), "
            "HNDL-exposed or internet-facing key establishment, inventory gaps."
        ),
        "focus": (
            "Remediate classically broken/deprecated primitives, address HNDL-exposed confidentiality paths "
            "through algorithm migration or hybridization (rotating keys/certificates only where key hygiene, "
            "expiry, weakness, or compromise requires rotation), add hybrid handshakes, and stage urgent PQC replacements."
        ),
    },
    {
        "name": "Wave 2 — Post-quantum migration",
        "timeline": "3-12 months",
        "criteria": (
            "Remaining Shor-vulnerable public-key primitives (RSA, ECDSA, ECDH, DH, Ed25519), "
            "hybrid KEM deployment, PQC signature migration, certificate chain rotation."
        ),
        "focus": (
            "Systematically move public-key signatures and key exchange to approved post-quantum "
            "mechanisms (ML-KEM / ML-DSA), covering downstream trust chains."
        ),
    },
    {
        "name": "Wave 3 — Symmetric hardening & governance",
        "timeline": "12-24 months",
        "criteria": (
            "Symmetric cipher consolidation (AES-256-GCM), hash strengthening, "
            "governance codification, crypto policy guardrails in CI."
        ),
        "focus": (
            "Consolidate symmetric modes (AES-256-GCM), strengthen hashes to SHA-256+/SHA-3, "
            "retire legacy ciphers, and codify crypto policy so new failures cannot ship."
        ),
    },
]


# ---------------------------------------------------------------------------
# Effort estimation model (Phase D)
# ---------------------------------------------------------------------------

# Base effort per asset type (in engineering weeks, low/high)
_EFFORT_PER_TYPE = {
    "PUBLIC_KEY": (2.0, 6.0),
    "SYMMETRIC": (0.5, 2.0),
    "CLASSICAL_WEAK": (1.0, 3.0),
    "HASH": (0.5, 1.5),
    "LEGACY_REVIEW": (0.5, 2.0),
    "UNKNOWN": (1.0, 4.0),
}


def compute_effort_range(
    assets: List[Dict[str, Any]],
    shared_dependencies: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """Compute effort estimate as a range (low/high) in engineering quarters.

    Model: effort = sum(base_effort[type] * blast_radius_factor) / dedup_factor
    where dedup_factor accounts for shared dependencies (one fix = one task).

    Assumptions are documented in the output for transparency.
    """
    if not assets:
        return {
            "low_weeks": 0.0, "high_weeks": 0.0,
            "low_quarters": 0.0, "high_quarters": 0.0,
            "assumptions": ["No assets to estimate."],
        }

    shared = shared_dependencies or {}
    total_low = 0.0
    total_high = 0.0
    seen_fixes = set()  # Deduplicate shared-dependency fixes

    for a in assets:
        category = str(a.get("algorithm_category") or a.get("replacement_category") or "UNKNOWN").upper()
        algo = normalize_algorithm(a.get("algorithm"))
        service = a.get("service") or "unknown"
        blast_count = a.get("blast", {}).get("shared_assets", 1)

        # Deduplicate: if this algo+service was already counted, skip
        fix_key = f"{algo}:{service}"
        if fix_key in seen_fixes:
            continue
        seen_fixes.add(fix_key)

        low, high = _EFFORT_PER_TYPE.get(category, (1.0, 4.0))

        # Blast radius factor: more shared assets = slightly more effort
        blast_factor = 1.0 + (0.1 * min(blast_count - 1, 10))

        total_low += low * blast_factor
        total_high += high * blast_factor

    # Convert weeks to quarters (13 weeks per quarter)
    low_q = round(total_low / 13.0, 1)
    high_q = round(total_high / 13.0, 1)

    return {
        "low_weeks": round(total_low, 1),
        "high_weeks": round(total_high, 1),
        "low_quarters": low_q,
        "high_quarters": high_q,
        "deduplicated_tasks": len(seen_fixes),
        "assumptions": [
            "Effort per asset type based on industry PQC migration benchmarks.",
            "Blast radius factor: +10% per co-located shared asset (capped at +100%).",
            "Shared-dependency fixes are deduplicated (one library = one task).",
            f"{len(seen_fixes)} unique fix tasks identified from {len(assets)} asset(s).",
        ],
    }


# ---------------------------------------------------------------------------
# Standards profile (Phase D)
# ---------------------------------------------------------------------------

NIST_GENERAL_RECOMMENDATIONS = {
    "kem": "ML-KEM-768 / ML-KEM-1024 (FIPS 203)",
    "signature": "ML-DSA-65 / ML-DSA-87 (FIPS 204) / SLH-DSA (FIPS 205)",
    "symmetric": "AES-256-GCM / ChaCha20-Poly1305",
    "hash": "SHA-256 / SHA-384 / SHA-512 / SHA-3",
    "firmware_signing": "ML-DSA-87 / SLH-DSA (FIPS 205)",
}

CNSA_2_0_RECOMMENDATIONS = {
    "kem": "ML-KEM-1024 (FIPS 203)",
    "signature": "ML-DSA-87 (FIPS 204)",
    "symmetric": "AES-256",
    "hash": "SHA-384 / SHA-512",
    "firmware_signing": "LMS / XMSS (stateful hash-based)",
}


def get_standards_recommendations(profile: str = "nist_general") -> Dict[str, str]:
    """Get role-specific PQC recommendations for the given standards profile."""
    if profile == "cnsa_2_0":
        return CNSA_2_0_RECOMMENDATIONS
    return NIST_GENERAL_RECOMMENDATIONS


def baseline_recommendations(bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    assets = bundle.get("assets") or []
    if not assets:
        return [
            {
                "priority": "LOW",
                "wave": 1,
                "title": "Continuous Cryptographic Posture Monitoring",
                "description": (
                    "No cryptographic assets were detected in this scope. "
                    "Establish automated CBOM discovery in CI to monitor new dependencies."
                ),
                "actions": [
                    "Maintain continuous discovery scans on code repositories",
                    "Enforce approved cryptographic algorithm policy in pull requests",
                ],
            }
        ]

    app_name = bundle.get("application") or bundle.get("target") or "Scanned Target"
    exposure = exposure_for(bundle)

    # 1. Classical-weak primitives (MD5, SHA-1, DES, 3DES, RC4, etc.)
    classical_weak_assets = [
        a for a in assets
        if normalize_algorithm(a.get("algorithm")) in ("MD5", "SHA1", "SHA-1", "DES", "3DES", "RC4", "RC2", "BLOWFISH")
        or (a.get("classical_security") or "").upper() in ("BROKEN", "LEGACY_DEPRECATED", "WEAK")
    ]

    # 2. HNDL-exposed assets
    hndl_assets = [
        a for a in assets
        if (a.get("hndl_risk") or "").upper() in ("HIGH", "CRITICAL")
        or a.get("hndl_status") == "APPLICABLE"
        or (isinstance(a.get("hndl"), dict) and a.get("hndl", {}).get("applicable"))
        or (isinstance(a.get("cbom_asset"), dict) and a.get("cbom_asset", {}).get("hndl_status") == "APPLICABLE")
    ]

    # 3. Shor / Quantum-vulnerable public-key assets
    shor_vulnerable_assets = [
        a for a in assets
        if a.get("quantum_vulnerable")
        or (a.get("algorithm_category") or "").upper() == "PUBLIC_KEY"
        or any(k in normalize_algorithm(a.get("algorithm")) for k in ("RSA", "ECC", "ECDSA", "ECDH", "ED25519", "DSA", "DH", "X25519"))
    ]

    # 4. Symmetric encryption and hashing
    symmetric_assets = [
        a for a in assets
        if (a.get("algorithm_category") or "").upper() in ("SYMMETRIC", "HASH")
        and not a.get("quantum_vulnerable")
        and a not in classical_weak_assets
    ]

    # 5. PQC-ready assets
    pqc_ready_assets = [
        a for a in assets
        if any(k in normalize_algorithm(a.get("algorithm")) for k in ("MLKEM", "ML-KEM", "MLDSA", "ML-DSA", "SLHDSA", "SLH-DSA", "FALCON", "KYBER", "DILITHIUM", "SPHINCS"))
        or (a.get("overall_risk") or "").upper() in ("PQC", "READY", "SAFE")
    ]

    recs: List[Dict[str, Any]] = []

    # Recommendation 1: Classical Broken/Deprecated Primitives
    if classical_weak_assets:
        weak_algos = sorted({(a.get("algorithm") or "unknown").upper() for a in classical_weak_assets})
        weak_algos_str = ", ".join(weak_algos)
        actions = []
        if any("MD5" in alg or "SHA" in alg for alg in weak_algos):
            actions.append("Replace broken digests (MD5, SHA-1) with SHA-256 or SHA-384")
        if any(alg in ("DES", "3DES", "RC4", "RC2", "BLOWFISH") for alg in weak_algos):
            actions.append("Migrate legacy ciphers (DES, 3DES, RC4) to AES-256-GCM")
        actions.append("Audit hardcoded keys or initialization vectors associated with legacy primitives")

        recs.append({
            "priority": "URGENT" if any((a.get("migration_priority") or "").upper() == "URGENT" for a in classical_weak_assets) else "HIGH",
            "wave": 1,
            "title": f"Legacy & Deprecated Primitive Remediation ({weak_algos_str})",
            "description": (
                f"{len(classical_weak_assets)} asset(s) utilize broken/deprecated algorithms ({weak_algos_str}). "
                "These fail classical security standards (NIST SP 800-131A) and require immediate replacement "
                "before post-quantum cryptographic transitions."
            ),
            "actions": actions or ["Replace deprecated algorithms with NIST-approved primitives (AES-256-GCM, SHA-256+)"],
        })

    # Recommendation 2: HNDL Exposure
    if hndl_assets:
        hndl_algos = sorted({(a.get("algorithm") or "unknown").upper() for a in hndl_assets})
        hndl_algos_str = ", ".join(hndl_algos)
        recs.append({
            "priority": "URGENT",
            "wave": 1,
            "title": f"Harvest-Now-Decrypt-Later (HNDL) Threat Remediation ({hndl_algos_str})",
            "description": (
                f"{len(hndl_assets)} asset(s) using ({hndl_algos_str}) protect data whose shelf-life extends into the "
                f"quantum horizon on an {exposure} attack surface. Eavesdropped ciphertext is at risk of retroactive decryption."
            ),
            "actions": [
                "Deploy hybrid key establishment (e.g. X25519 + ML-KEM-768) on TLS & key exchange endpoints",
                "Re-encrypt sensitive archived datasets using post-quantum safe encapsulation",
                "Enforce short certificate lifetimes and immediate rotation for exposed long-term keys",
            ],
        })

    # Recommendation 3: Shor-Vulnerable Public-Key Infrastructure
    if shor_vulnerable_assets:
        shor_algos = sorted({(a.get("algorithm") or "unknown").upper() for a in shor_vulnerable_assets})
        shor_algos_str = ", ".join(shor_algos)
        has_kem = any(any(k in alg for k in ("RSA", "DH", "ECDH", "X25519")) for alg in shor_algos)
        has_sig = any(any(k in alg for k in ("RSA", "DSA", "ECDSA", "ED25519")) for alg in shor_algos)

        actions = []
        if has_kem:
            actions.append("Migrate public-key exchange & encryption to NIST FIPS 203 (ML-KEM-768/1024)")
        if has_sig:
            actions.append("Migrate digital signatures & PKI identity to NIST FIPS 204 (ML-DSA-65/87)")
        actions.append(f"Upgrade crypto provider libraries to PQC-enabled toolchains across {exposure} services")

        urgent_count = sum(1 for a in shor_vulnerable_assets if (a.get("migration_priority") or "").upper() == "URGENT")
        recs.append({
            "priority": "URGENT" if urgent_count > 0 else "HIGH",
            "wave": 2,
            "title": f"Post-Quantum Public-Key Transition ({shor_algos_str})",
            "description": (
                f"{len(shor_vulnerable_assets)} public-key asset(s) ({shor_algos_str}) are vulnerable to polynomial-time "
                f"quantum cryptanalysis (Shor's algorithm). Execute phased rollout to NIST FIPS 203 & 204 standards."
            ),
            "actions": actions,
        })

    # Recommendation 4: Symmetric Hardening & Grover Margin
    if symmetric_assets:
        sym_algos = sorted({(a.get("algorithm") or "unknown").upper() for a in symmetric_assets})
        has_128 = any("128" in alg for alg in sym_algos)
        actions = [
            "Standardize on AES-256-GCM as the default cipher suite for all data-at-rest and in-transit encryption",
            "Adopt SHA-256 or SHA-3 for digital digests, HMACs, and integrity validation",
        ]
        if has_128:
            actions.insert(0, "Upgrade 128-bit key configurations to 256-bit keys to preserve 128-bit quantum security against Grover")

        recs.append({
            "priority": "MEDIUM",
            "wave": 3,
            "title": f"Symmetric & Digest Resilience Hardening ({', '.join(sym_algos)})",
            "description": (
                f"Audit {len(symmetric_assets)} symmetric & hashing asset(s). Consolidate configurations to 256-bit keys "
                "to ensure adequate security margins against quantum acceleration."
            ),
            "actions": actions,
        })

    # Recommendation 5: PQC-Ready Asset Verification (if applicable)
    if pqc_ready_assets:
        pqc_algos = sorted({(a.get("algorithm") or "unknown").upper() for a in pqc_ready_assets})
        recs.append({
            "priority": "LOW",
            "wave": 3,
            "title": f"Verified Post-Quantum Asset Maintenance ({', '.join(pqc_algos)})",
            "description": (
                f"{len(pqc_ready_assets)} asset(s) already utilize approved post-quantum or quantum-resistant primitives. "
                "Maintain operational compliance and track ongoing NIST FIPS errata."
            ),
            "actions": [
                "Verify parameter set configurations against NIST Special Publication benchmarks",
                "Ensure cryptographic agility to accommodate future parameter updates",
            ],
        })

    # Recommendation 6: Governance & Pipeline Guardrails
    recs.append({
        "priority": "MEDIUM",
        "wave": 3,
        "title": f"Cryptographic Agility & CI/CD Governance ({app_name})",
        "description": (
            f"Establish automated CBOM discovery and cryptographic linting in the build pipelines for {app_name}. "
            "Prevent regressions and stop unapproved cryptographic algorithms at the pull request stage."
        ),
        "actions": [
            f"Embed automated ECDAT CBOM generation into {app_name} CI/CD workflows",
            "Codify an organization-wide Approved Cryptographic Algorithms Policy",
            "Schedule quarterly quantum readiness re-assessments and audit trail reviews",
        ],
    })

    return recs