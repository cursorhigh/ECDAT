"""Normalization engine (Segment A).

Takes a RawFinding and produces a NormalizedFinding: deduplicates,
maps raw fields to canonical fields, and records a confidence score.
"""

import logging

from .models import NormalizedFinding, RawFinding, ScanJob

logger = logging.getLogger(__name__)

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
    "des": NormalizedFinding.AlgorithmFamily.DES3,
    "des3": NormalizedFinding.AlgorithmFamily.DES3,
    "3des": NormalizedFinding.AlgorithmFamily.DES3,
    "tripledes": NormalizedFinding.AlgorithmFamily.DES3,
    "triple-des": NormalizedFinding.AlgorithmFamily.DES3,
    "hash": NormalizedFinding.AlgorithmFamily.HASH,
    "sha": NormalizedFinding.AlgorithmFamily.HASH,
    "md5": NormalizedFinding.AlgorithmFamily.HASH,
    "mac": NormalizedFinding.AlgorithmFamily.MAC,
    "hmac": NormalizedFinding.AlgorithmFamily.MAC,
    "pqc": NormalizedFinding.AlgorithmFamily.PQC,
    "ml-kem": NormalizedFinding.AlgorithmFamily.PQC,
    "ml-dsa": NormalizedFinding.AlgorithmFamily.PQC,
    "slh-dsa": NormalizedFinding.AlgorithmFamily.PQC
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
    if algo.startswith(("3des", "des", "tripledes")):
        return NormalizedFinding.AlgorithmFamily.DES3
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

    try:
        family = _normalize_family(data.get("family", ""))
        if family == NormalizedFinding.AlgorithmFamily.UNKNOWN:
            family = _guess_family_from_algorithm(data.get("algorithm", ""))
    except Exception:
        # A classification bug must never fail an entire scan job; degrade the
        # family and keep the finding so evidence is not lost.
        logger.exception("Family classification failed for raw finding %s", raw.pk)
        family = NormalizedFinding.AlgorithmFamily.UNKNOWN

    kind = _normalize_kind(data.get("kind", ""))
    evidence = data.get("evidence") if isinstance(data.get("evidence"), dict) else {}
    line = data.get("line") if isinstance(data.get("line"), int) else None

    dedup_key = _build_dedup_key(data)
    db = using or raw._state.db or "default"

    norm, created = NormalizedFinding.objects.using(db).get_or_create(
        raw_finding=raw,
        defaults={
            "mode": raw.mode,
            "session_id": session_id,
            "kind": kind,
            "family": family,
            "algorithm": data.get("algorithm", ""),
            "key_size": data.get("key_size") or None,
            "curve": data.get("curve", ""),
            "protocol": data.get("protocol", ""),
            "library": data.get("library", ""),
            "library_version": data.get("library_version", ""),
            "confidence": data.get("confidence", 0.0),
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
