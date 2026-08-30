"""Crypto Asset Classifier (Segment A).

Consolidates normalized findings into canonical CryptoAsset records.
A simple, deterministic classifier for this phase; can be upgraded to
an ML/AI-assisted classifier later without changing the interface.
"""

from .models import CryptoAsset, NormalizedFinding, ScanJob
from core.models import log_action


def _asset_name(norm: NormalizedFinding, source_type: str) -> str:
    algo = norm.algorithm or norm.family
    bits = f" {norm.key_size}" if norm.key_size else ""
    curve = f" ({norm.curve})" if norm.curve else ""
    source = ScanJob.SourceType(source_type).label if source_type else source_type
    return f"{algo}{bits}{curve} — {source}"


def classify_asset(norm: NormalizedFinding, using=None) -> CryptoAsset:
    """Create or refresh the canonical CryptoAsset for a normalized finding."""
    location = norm.raw_finding.location
    source_type = norm.raw_finding.source_type
    db = using or norm._state.db or "default"

    name = _asset_name(norm, source_type)
    asset, created = CryptoAsset.objects.using(db).get_or_create(
        name=name,
        defaults={
            "mode": norm.mode,
            "family": norm.family,
            "algorithm": norm.algorithm,
            "key_size": norm.key_size,
            "curve": norm.curve,
            "protocol": norm.protocol,
            "library": norm.library,
            "library_version": norm.library_version,
            "source_type": source_type,
            "location": location,
            "owner": _infer_owner(location),
        },
    )
    if created:
        log_action("system", f"Created crypto asset {name}", "cryptoasset", asset.pk, mode=norm.mode)
    asset.normalized_findings.add(norm)
    return asset


def _infer_owner(location: str) -> str:
    """Best-effort owner inference from a repo-ish location."""
    base = (location or "").split("/")[0].lower()
    mapping = {
        "payments": "Payments",
        "identity": "Identity",
        "data": "Data Platform",
        "partners": "Partners",
        "core": "Platform Core",
    }
    return mapping.get(base, "Unknown Owner")
