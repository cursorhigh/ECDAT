"""Normalization engine (Segment A).

Takes a RawFinding and produces a NormalizedFinding: deduplicates,
maps raw fields to canonical fields, and records a confidence score.

Phase A enhancements:
- Algorithm name canonicalization (case-insensitive, strip separators)
- API call name → underlying algorithm mapping
- Bare keyword exclusion (indicator/config evidence, not crypto assets)
- Key-size guard (never assign key_size to non-key findings like hashes)
- Evidence context tagging (source_context, evidence_confidence)
"""

import logging
import re

from .models import NormalizedFinding, RawFinding, ScanJob
from core.modes import active_mode

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Algorithm name canonicalization
# ---------------------------------------------------------------------------

# Canonical algorithm names: input variants → standard name.
# Applied case-insensitively after stripping hyphens/underscores/spaces.
_CANONICAL_ALGORITHM_MAP = {
    # Hash algorithms
    "sha1": "SHA-1",
    "sha224": "SHA-224",
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
    "sha3224": "SHA-3-224",
    "sha3256": "SHA-3-256",
    "sha3384": "SHA-3-384",
    "sha3512": "SHA-3-512",
    "md5": "MD5",
    "md4": "MD4",
    "md2": "MD2",
    "ripemd160": "RIPEMD-160",
    # Symmetric
    "aes": "AES",
    "aes128": "AES-128",
    "aes192": "AES-192",
    "aes256": "AES-256",
    "aes256gcm": "AES-256-GCM",
    "aes128gcm": "AES-128-GCM",
    "des": "DES",
    "3des": "3DES",
    "desede": "3DES",
    "tripledes": "3DES",
    "des3": "3DES",
    "blowfish": "Blowfish",
    "blowfish128": "Blowfish-128",
    "rc4": "RC4",
    "rc2": "RC2",
    "chacha20": "ChaCha20",
    "chacha20poly1305": "ChaCha20-Poly1305",
    "camellia": "Camellia",
    # Asymmetric
    "rsa": "RSA",
    "rsa2048": "RSA-2048",
    "rsa3072": "RSA-3072",
    "rsa4096": "RSA-4096",
    "rsa1024": "RSA-1024",
    "ecdsa": "ECDSA",
    "ecdsap256": "ECDSA-P256",
    "ecdsap384": "ECDSA-P384",
    "ecdh": "ECDH",
    "ed25519": "Ed25519",
    "ed448": "Ed448",
    "x25519": "X25519",
    "x448": "X448",
    "dsa": "DSA",
    "dh": "DH",
    "elgamal": "ElGamal",
    # PQC
    "mlkem": "ML-KEM",
    "mlkem768": "ML-KEM-768",
    "mlkem1024": "ML-KEM-1024",
    "mldsa": "ML-DSA",
    "mldsa65": "ML-DSA-65",
    "mldsa87": "ML-DSA-87",
    "slhdsa": "SLH-DSA",
    "kyber": "Kyber",
    "dilithium": "Dilithium",
    "falcon": "Falcon",
    "sphincs": "SPHINCS+",
    "xmss": "XMSS",
    "lms": "LMS",
    # MAC
    "hmac": "HMAC",
    "hmacsha1": "HMAC-SHA-1",
    "hmacsha256": "HMAC-SHA-256",
    "hmacsha384": "HMAC-SHA-384",
    "hmacsha512": "HMAC-SHA-512",
    "cmac": "CMAC",
    "gmac": "GMAC",
    "poly1305": "Poly1305",
}

# API/call names → (canonical algorithm, canonical family)
_API_NAME_MAP = {
    # Go standard library
    "md5.new": ("MD5", "hash"),
    "sha1.new": ("SHA-1", "hash"),
    "sha256.new": ("SHA-256", "hash"),
    "sha512.new": ("SHA-512", "hash"),
    "rsa.generatekey": ("RSA", "rsa"),
    "ecdsa.generatekey": ("ECDSA", "ecc"),
    "aes.newcipher": ("AES", "aes"),
    "hmac.new": ("HMAC", "mac"),
    # Node.js / browser
    "crypto.createcipheriv": ("AES", "aes"),
    "crypto.createhmac": ("HMAC", "mac"),
    "crypto.createhash": ("HASH", "hash"),
    "crypto.createsign": ("RSA", "rsa"),
    "crypto.createverify": ("RSA", "rsa"),
    # Python standard library
    "hashlib.md5": ("MD5", "hash"),
    "hashlib.sha1": ("SHA-1", "hash"),
    "hashlib.sha256": ("SHA-256", "hash"),
    "hashlib.sha384": ("SHA-384", "hash"),
    "hashlib.sha512": ("SHA-512", "hash"),
    "hashlib.sha3_256": ("SHA-3-256", "hash"),
    "hashlib.sha3_512": ("SHA-3-512", "hash"),
    # Python cryptography library
    "rsa.generate_private_key": ("RSA", "rsa"),
    "ec.generate_private_key": ("ECDSA", "ecc"),
    "dsa.generate_private_key": ("DSA", "dsa"),
    "dh.generate_parameters": ("DH", "dh"),
    "x25519.x25519privatekey.generate": ("X25519", "ecc"),
    "ed25519.ed25519privatekey.generate": ("Ed25519", "ecc"),
    # Class / type names
    "ed25519privatekey": ("Ed25519", "ecc"),
    "ed25519publickey": ("Ed25519", "ecc"),
    "x25519privatekey": ("X25519", "ecc"),
    "x25519publickey": ("X25519", "ecc"),
    "rsaprivatekey": ("RSA", "rsa"),
    "rsapublickey": ("RSA", "rsa"),
    "ecdsasignature": ("ECDSA", "ecc"),
}

# ---------------------------------------------------------------------------
# Bare keyword exclusion — these are NOT cryptographic assets
# ---------------------------------------------------------------------------

_INDICATOR_KEYWORDS = frozenset({
    "crypto", "key", "tls", "ssl", "hash", "cipher",
    "openssl_conf", "ssh_host_key", "tls_ciphers",
    "openssl", "boringssl", "libssl", "libcrypto",
    "encryption", "decryption", "signature", "digest",
    "certificate", "keystore", "truststore",
})

# These match only when the algorithm field is EXACTLY one of these bare words
# (case-insensitive, after stripping), with no further qualifying information.
_BARE_KEYWORD_PATTERN = re.compile(
    r"^(?:crypto|key|tls|ssl|hash|cipher|openssl_conf|ssh_host_key|"
    r"tls_ciphers|openssl|boringssl|libssl|libcrypto|encryption|"
    r"decryption|signature|digest|certificate|keystore|truststore)$",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Evidence context classification
# ---------------------------------------------------------------------------

_SOURCE_CONTEXT_MAP = {
    "test": "test",
    "tests": "test",
    "test_": "test",
    "_test.": "test",
    "spec": "test",
    "spec/": "test",
    "__tests__": "test",
    "example": "example",
    "examples": "example",
    "sample": "example",
    "doc": "docs",
    "docs": "docs",
    "readme": "docs",
    "changelog": "docs",
    "comment": "comment",
}

# Confidence levels for evidence sources
EVIDENCE_CONFIDENCE = {
    "certificate": 0.95,
    "key": 0.95,
    "live_code": 0.90,
    "config": 0.80,
    "binary": 0.80,
    "container": 0.75,
    "dependency": 0.70,
    "test": 0.40,
    "example": 0.35,
    "docs": 0.25,
    "comment": 0.20,
    "unknown": 0.50,
}


def _infer_source_context(location: str, kind: str, source_type: str) -> str:
    """Infer evidence source context from location, kind, and source type."""
    loc_lower = (location or "").lower().replace("\\", "/")
    kind_lower = (kind or "").lower()

    # Kind-based context takes precedence
    if kind_lower in ("certificate", "key", "key_reference"):
        return kind_lower if kind_lower != "key_reference" else "key"

    # Source type overrides
    if source_type in ("certificate",):
        return "certificate"
    if source_type in ("binary",):
        return "binary"
    if source_type in ("container",):
        return "container"
    if source_type in ("dependency",):
        return "dependency"

    # Location-based inference
    for token, ctx in _SOURCE_CONTEXT_MAP.items():
        if token in loc_lower:
            return ctx

    # Config files
    config_patterns = (".conf", ".cfg", ".ini", ".yaml", ".yml", ".toml", ".env", ".properties")
    if any(loc_lower.endswith(p) for p in config_patterns):
        return "config"

    return "live_code"


def _compute_evidence_confidence(source_context: str, base_confidence: float) -> float:
    """Compute evidence confidence from source context and scanner base confidence."""
    ctx_weight = EVIDENCE_CONFIDENCE.get(source_context, 0.50)
    if base_confidence > 0.0:
        return round(min(1.0, (base_confidence + ctx_weight) / 2.0), 3)
    return ctx_weight


# ---------------------------------------------------------------------------
# Core canonicalization
# ---------------------------------------------------------------------------

def canonicalize_algorithm(raw: str) -> str:
    """Canonicalize an algorithm name: case-insensitive, strip separators,
    map API names and common variants to a single canonical form.

    Returns the canonical name, or the cleaned original if no mapping exists.
    """
    if not raw:
        return ""
    cleaned = raw.strip()
    # Try API name mapping first (preserves dots)
    api_key = cleaned.lower().replace(" ", "")
    if api_key in _API_NAME_MAP:
        return _API_NAME_MAP[api_key][0]

    # Strip hyphens, underscores, spaces for lookup
    normalized = cleaned.lower().replace("-", "").replace("_", "").replace(" ", "")
    if normalized in _API_NAME_MAP:
        return _API_NAME_MAP[normalized][0]
    if normalized in _CANONICAL_ALGORITHM_MAP:
        return _CANONICAL_ALGORITHM_MAP[normalized]

    # Return the original cleaned string with consistent casing if no mapping
    return cleaned


def is_bare_indicator(algorithm: str, family: str = "", kind: str = "") -> bool:
    """Return True if this finding is just a bare keyword/indicator, not a
    real cryptographic asset. These should be tagged as 'indicator/config evidence'
    rather than counted in asset totals."""
    algo_clean = (algorithm or "").strip()
    if not algo_clean:
        return True
    if _BARE_KEYWORD_PATTERN.match(algo_clean) or algo_clean.lower() in _INDICATOR_KEYWORDS:
        return True
    return False


# ---------------------------------------------------------------------------
# Key-size validation
# ---------------------------------------------------------------------------

# Families where key_size is meaningful
_KEY_SIZE_FAMILIES = frozenset({"rsa", "dsa", "dh", "ecc", "aes", "des3", "unknown"})
# Families where key_size should NOT be applied (hash output size != key size)
_NO_KEY_SIZE_FAMILIES = frozenset({"hash", "mac"})


def _validate_key_size(key_size, family: str, algorithm: str) -> int | None:
    """Validate and sanitize key_size: never assign key sizes to non-key/indicator findings.
    Leave fields empty rather than inventing values."""
    if key_size is None:
        return None
    try:
        size = int(key_size)
    except (TypeError, ValueError):
        return None

    if size <= 0:
        return None

    fam_lower = (family or "").lower()
    algo_lower = (algorithm or "").lower().replace("-", "").replace("_", "").replace(" ", "")

    # Bare indicators and protocol keywords should NEVER carry key_size
    if algo_lower in _INDICATOR_KEYWORDS or _BARE_KEYWORD_PATTERN.match(algo_lower):
        return None

    # Hash algorithms, digests, MACs, protocols should NEVER carry key_size
    hash_indicators = ("sha", "md5", "md4", "md2", "ripemd", "blake", "shake", "hash", "digest", "tls", "ssl", "crypto", "ssh", "ipsec")
    if (
        fam_lower in _NO_KEY_SIZE_FAMILIES
        or fam_lower in ("protocol", "unknown", "digest")
        or any(algo_lower.startswith(h) or h in algo_lower for h in ("sha1", "sha2", "sha3", "sha512", "sha384", "sha256", "sha224", "md5", "md4", "blake", "ripemd", "shake"))
    ):
        return None

    # Only key-bearing families and genuine key algorithms may have key_size
    is_key_algo = any(k in algo_lower for k in ("rsa", "dsa", "dh", "ecc", "ecdsa", "ecdh", "aes", "des", "3des", "mlkem", "mldsa", "chacha"))
    if not is_key_algo or fam_lower in _NO_KEY_SIZE_FAMILIES:
        return None

    return size



# ---------------------------------------------------------------------------
# Family mapping
# ---------------------------------------------------------------------------

# Map raw 'family' strings to canonical families.
_FAMILY_MAP = {
    "rsa": NormalizedFinding.AlgorithmFamily.RSA,
    "ecc": NormalizedFinding.AlgorithmFamily.ECC,
    "ecdsa": NormalizedFinding.AlgorithmFamily.ECC,
    "ecdh": NormalizedFinding.AlgorithmFamily.ECC,
    "ed25519": NormalizedFinding.AlgorithmFamily.ECC,
    "x25519": NormalizedFinding.AlgorithmFamily.ECC,
    "dsa": NormalizedFinding.AlgorithmFamily.DSA,
    "dh": NormalizedFinding.AlgorithmFamily.DH,
    "aes": NormalizedFinding.AlgorithmFamily.AES,
    "des": NormalizedFinding.AlgorithmFamily.DES3,
    "des3": NormalizedFinding.AlgorithmFamily.DES3,
    "3des": NormalizedFinding.AlgorithmFamily.DES3,
    "tripledes": NormalizedFinding.AlgorithmFamily.DES3,
    "triple-des": NormalizedFinding.AlgorithmFamily.DES3,
    "hash": NormalizedFinding.AlgorithmFamily.HASH,
    "sha": NormalizedFinding.AlgorithmFamily.HASH,
    "md5": NormalizedFinding.AlgorithmFamily.HASH,
    "sha1": NormalizedFinding.AlgorithmFamily.HASH,
    "sha-1": NormalizedFinding.AlgorithmFamily.HASH,
    "sha256": NormalizedFinding.AlgorithmFamily.HASH,
    "sha-256": NormalizedFinding.AlgorithmFamily.HASH,
    "sha384": NormalizedFinding.AlgorithmFamily.HASH,
    "sha-384": NormalizedFinding.AlgorithmFamily.HASH,
    "sha512": NormalizedFinding.AlgorithmFamily.HASH,
    "sha-512": NormalizedFinding.AlgorithmFamily.HASH,
    "mac": NormalizedFinding.AlgorithmFamily.MAC,
    "hmac": NormalizedFinding.AlgorithmFamily.MAC,
    "pqc": NormalizedFinding.AlgorithmFamily.PQC,
    "ml-kem": NormalizedFinding.AlgorithmFamily.PQC,
    "ml-dsa": NormalizedFinding.AlgorithmFamily.PQC,
    "slh-dsa": NormalizedFinding.AlgorithmFamily.PQC,
}

# Canonical artefact kinds a scanner may report.
_VALID_KINDS = set(NormalizedFinding.FindingKind.values)


def _normalize_family(raw: str) -> str:
    key = (raw or "").strip().lower()
    return _FAMILY_MAP.get(key, NormalizedFinding.AlgorithmFamily.UNKNOWN)


def _normalize_kind(raw: str) -> str:
    """Map a scanner-supplied artefact kind onto the canonical vocabulary.

    An unrecognised kind degrades to `algorithm` rather than failing: the
    family already says what was observed, so a bad kind must not lose it.
    """
    key = (raw or "").strip().lower()
    return key if key in _VALID_KINDS else NormalizedFinding.FindingKind.ALGORITHM


def _guess_family_from_algorithm(algorithm: str) -> str:
    algo = (algorithm or "").lower().replace("-", "").replace("_", "")

    # Check API name map first
    api_key = (algorithm or "").lower().replace(" ", "")
    if api_key in _API_NAME_MAP:
        _, family = _API_NAME_MAP[api_key]
        return _FAMILY_MAP.get(family, NormalizedFinding.AlgorithmFamily.UNKNOWN)

    if algo.startswith("rsa"):
        return NormalizedFinding.AlgorithmFamily.RSA
    if algo.startswith(("ecdsa", "ecdh", "ed25519", "ed448", "x25519", "x448", "p256", "p384", "p521", "secp", "curve")):
        return NormalizedFinding.AlgorithmFamily.ECC
    if algo.startswith("ec") and len(algo) <= 4:
        return NormalizedFinding.AlgorithmFamily.ECC
    if algo.startswith("dsa"):
        return NormalizedFinding.AlgorithmFamily.DSA
    if algo.startswith("dh") or "diffiehellman" in algo:
        return NormalizedFinding.AlgorithmFamily.DH
    if algo.startswith("aes"):
        return NormalizedFinding.AlgorithmFamily.AES
    if algo.startswith(("3des", "des", "tripledes", "desede")):
        return NormalizedFinding.AlgorithmFamily.DES3
    if algo.startswith(("mlkem", "mldsa", "slhdsa")) or algo in ("kyber", "dilithium", "falcon", "sphincs", "xmss", "lms"):
        return NormalizedFinding.AlgorithmFamily.PQC
    if algo.startswith(("hmac", "cmac", "gmac", "poly1305")):
        return NormalizedFinding.AlgorithmFamily.MAC
    if algo.startswith(("sha", "md5", "md4", "md2", "ripemd", "blake", "hash")):
        return NormalizedFinding.AlgorithmFamily.HASH
    if algo in ("blowfish", "rc4", "rc2", "chacha20", "camellia", "aria"):
        # Legacy/symmetric ciphers without a dedicated family
        return NormalizedFinding.AlgorithmFamily.UNKNOWN

    return NormalizedFinding.AlgorithmFamily.UNKNOWN


def _build_dedup_key(data: dict, canonical_algo: str) -> str:
    parts = [
        data.get("family", ""),
        canonical_algo,
        str(data.get("key_size", "")),
        data.get("curve", ""),
        data.get("protocol", ""),
        data.get("location", ""),
    ]
    return "|".join(parts)


def normalize_finding(raw: RawFinding, using=None, session_id=None) -> NormalizedFinding:
    """Create/return a NormalizedFinding for a raw finding.

    `using` selects the database to write to (defaults to the raw finding's
    own database so the pipeline stays inside the correct mode boundary).

    `session_id` scopes the normalized finding to a work session. It defaults to
    the raw finding's own session: a normalized record always belongs to the
    same session as the evidence it came from, and deriving it here means a
    caller that forgets the argument cannot write a row that no session-scoped
    read will ever see.
    """
    if session_id is None:
        session_id = raw.session_id

    data = raw.raw_json or {}

    # Canonicalize algorithm name
    raw_algorithm = data.get("algorithm", "")
    canonical_algo = canonicalize_algorithm(raw_algorithm)

    try:
        family = _normalize_family(data.get("family", ""))
        if family == NormalizedFinding.AlgorithmFamily.UNKNOWN:
            family = _guess_family_from_algorithm(canonical_algo)
    except Exception:
        # A classification bug must never fail an entire scan job; degrade the
        # family and keep the finding so evidence is not lost.
        logger.exception("Family classification failed for raw finding %s", raw.pk)
        family = NormalizedFinding.AlgorithmFamily.UNKNOWN

    kind = _normalize_kind(data.get("kind", ""))

    # Evidence context and confidence
    evidence = data.get("evidence") if isinstance(data.get("evidence"), dict) else {}
    source_context = _infer_source_context(
        raw.location or "", kind, raw.source_type or ""
    )
    base_conf = data.get("confidence", 0.0)
    evidence_confidence = _compute_evidence_confidence(source_context, base_conf)

    # Enrich evidence with context metadata
    evidence["source_context"] = source_context
    evidence["evidence_confidence"] = evidence_confidence

    # Propagate operational context and threat metadata
    for op_key in (
        "exposure", "network_exposure", "public_endpoint", "internet_facing",
        "hndl_exposure", "hndl_risk", "data_shelf_life_years", "data_lifetime_years",
        "data_sensitivity", "migration_time_years", "quantum_horizon_years",
        "role", "purpose", "exploitability_score", "asset_id",
    ):
        if op_key in data and op_key not in evidence:
            evidence[op_key] = data[op_key]

    if data.get("public_endpoint") or data.get("internet_facing"):
        evidence["public_endpoint"] = True
        evidence["internet_facing"] = True
    elif str(data.get("exposure") or data.get("network_exposure") or "").lower() in ("internet", "internet-facing", "public", "external"):
        evidence["public_endpoint"] = True
        evidence["internet_facing"] = True

    if data.get("hndl_exposure") or data.get("hndl_risk"):
        h_val = str(data.get("hndl_exposure") or data.get("hndl_risk")).upper()
        evidence["hndl_exposure"] = h_val
        evidence["hndl_risk"] = h_val

    # Tag bare indicators
    if is_bare_indicator(canonical_algo, family, kind):
        evidence["is_indicator"] = True
        evidence["indicator_note"] = (
            f"'{canonical_algo}' is a bare keyword/indicator, not a concrete "
            "cryptographic algorithm. Reclassified as indicator/config evidence."
        )

    line = data.get("line") if isinstance(data.get("line"), int) else None

    # Validate key_size (never assign key sizes to hashes)
    validated_key_size = _validate_key_size(
        data.get("key_size"), family, canonical_algo
    )

    dedup_key = _build_dedup_key(data, canonical_algo)
    db = using or raw._state.db or "default"

    norm, created = NormalizedFinding.objects.using(db).get_or_create(
        raw_finding=raw,
        defaults={
            "session_id": session_id,
            "kind": kind,
            "family": family,
            "algorithm": canonical_algo,
            "key_size": validated_key_size,
            "curve": data.get("curve", ""),
            "protocol": data.get("protocol", ""),
            "library": data.get("library", ""),
            "library_version": data.get("library_version", ""),
            "confidence": evidence_confidence,
            "dedup_key": dedup_key,
            "line": line,
            "evidence": evidence,
        },
    )
    if created:
        raw.status = RawFinding.Status.NORMALIZED
        raw.save(using=db, update_fields=["status"])
    return norm


def canonical_kind_counts(queryset) -> dict[str, int]:
    """Count normalized findings per canonical artefact kind.

    Only kinds in the canonical vocabulary are reported; a row carrying a kind
    outside it is counted under the unknown bucket rather than inflating a real
    category with a value the UI cannot label.
    """
    from .models import NormalizedFinding

    counts = {kind: 0 for kind in NormalizedFinding.FindingKind.values}
    rows = queryset.values_list("kind", flat=True)
    for kind in rows:
        key = kind if kind in _VALID_KINDS else NormalizedFinding.FindingKind.UNKNOWN
        counts[key] = counts.get(key, 0) + 1
    return {kind: count for kind, count in counts.items() if count}
