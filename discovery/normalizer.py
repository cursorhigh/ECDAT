"""Normalization engine (Segment A).

Takes a RawFinding and produces a NormalizedFinding: deduplicates,
maps raw fields to canonical fields, and records a confidence score.
"""

from .models import NormalizedFinding, RawFinding, ScanJob

# Map raw 'family' strings to canonical families.
_FAMILY_MAP = {
    "rsa": NormalizedFinding.AlgorithmFamily.RSA,
    "ecc": NormalizedFinding.AlgorithmFamily.ECC,
    "ecdsa": NormalizedFinding.AlgorithmFamily.ECC,
    "ecdh": NormalizedFinding.AlgorithmFamily.ECC,
    "ed25519": NormalizedFinding.AlgorithmFamily.ECC,
    "dsa": NormalizedFinding.AlgorithmFamily.DSA,
    "dh": NormalizedFinding.AlgorithmFamily.DH,
    "aes": NormalizedFinding.AlgorithmFamily.AES,
    "hash": NormalizedFinding.AlgorithmFamily.HASH,
    "sha": NormalizedFinding.AlgorithmFamily.HASH,
    "md5": NormalizedFinding.AlgorithmFamily.HASH,
    "mac": NormalizedFinding.AlgorithmFamily.MAC,
    "hmac": NormalizedFinding.AlgorithmFamily.MAC,
    "pqc": NormalizedFinding.AlgorithmFamily.PQC,
    "ml-kem": NormalizedFinding.AlgorithmFamily.PQC,
    "ml-dsa": NormalizedFinding.AlgorithmFamily.PQC,
    "slh-dsa": NormalizedFinding.AlgorithmFamily.PQC,
}


def _normalize_family(raw: str) -> str:
    key = (raw or "").strip().lower()
    return _FAMILY_MAP.get(key, NormalizedFinding.AlgorithmFamily.UNKNOWN)


def _guess_family_from_algorithm(algorithm: str) -> str:
    algo = (algorithm or "").lower()
    if algo.startswith("rsa"):
        return NormalizedFinding.AlgorithmFamily.RSA
    if algo.startswith(("ec", "ed", "p-", "x25519", "curve")):
        return NormalizedFinding.AlgorithmFamily.ECC
    if algo.startswith("dsa"):
        return NormalizedFinding.AlgorithmFamily.DSA
    if algo.startswith("dh"):
        return NormalizedFinding.AlgorithmFamily.DH
    if algo.startswith("aes"):
        return NormalizedFinding.AlgorithmFamily.AES
    if algo.startswith("ml-") or algo.startswith("slh-"):
        return NormalizedFinding.AlgorithmFamily.PQC
    if algo.startswith(("sha", "md", "hash")):
        return NormalizedFinding.AlgorithmFamily.HASH
    return NormalizedFinding.AlgorithmFamily.UNKNOWN


def _build_dedup_key(raw: dict) -> str:
    parts = [
        raw.get("family", ""),
        raw.get("algorithm", ""),
        str(raw.get("key_size", "")),
        raw.get("curve", ""),
        raw.get("protocol", ""),
        raw.get("location", ""),
    ]
    return "|".join(parts)


def normalize_finding(raw: RawFinding, using=None) -> NormalizedFinding:
    """Create/return a NormalizedFinding for a raw finding.

    `using` selects the database to write to (defaults to the raw finding's
    own database so the pipeline stays inside the correct mode boundary).
    """
    data = raw.raw_json or {}

    family = _normalize_family(data.get("family", ""))
    if family == NormalizedFinding.AlgorithmFamily.UNKNOWN:
        family = _guess_family_from_algorithm(data.get("algorithm", ""))

    dedup_key = _build_dedup_key(data)
    db = using or raw._state.db or "default"

    norm, created = NormalizedFinding.objects.using(db).get_or_create(
        raw_finding=raw,
        defaults={
            "mode": raw.mode,
            "family": family,
            "algorithm": data.get("algorithm", ""),
            "key_size": data.get("key_size") or None,
            "curve": data.get("curve", ""),
            "protocol": data.get("protocol", ""),
            "library": data.get("library", ""),
            "library_version": data.get("library_version", ""),
            "confidence": data.get("confidence", 0.0),
            "dedup_key": dedup_key,
        },
    )
    if created:
        raw.status = RawFinding.Status.NORMALIZED
        raw.save(using=db, update_fields=["status"])
    return norm
