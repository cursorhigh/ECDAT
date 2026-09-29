"""Crypto asset classification.

An asset is the *thing* that carries cryptography; a family is what was
observed on it; an occurrence is where it was seen. Keeping those three apart
is what lets the inventory answer "one RSA implementation used in twenty
applications" instead of returning twenty unrelated rows -- and it fixes the
previous behaviour where an asset's location and owner were written once and
never updated when a later sighting showed better information.
"""

from __future__ import annotations

import hashlib

from .models import AssetOccurrence, CryptoAsset, NormalizedFinding, ScanJob
from core.models import log_action
from core.modes import active_mode

# Kinds that identify the artefact regardless of how it was found: a
# certificate is a certificate whether it sits in a .pem file or inside an
# executable.
_KIND_TO_ASSET_TYPE = {
    "certificate": CryptoAsset.AssetType.CERTIFICATE,
    "key": CryptoAsset.AssetType.KEY_REFERENCE,
    "key_reference": CryptoAsset.AssetType.KEY_REFERENCE,
    "library": CryptoAsset.AssetType.LIBRARY,
    "dependency": CryptoAsset.AssetType.DEPENDENCY,
    "cloud_crypto_service": CryptoAsset.AssetType.CLOUD_RESOURCE,
    "hardware_module": CryptoAsset.AssetType.HARDWARE,
    "network_endpoint": CryptoAsset.AssetType.NETWORK_ENDPOINT,
    "external_service": CryptoAsset.AssetType.EXTERNAL_SERVICE,
    "api": CryptoAsset.AssetType.API,
}

# Kinds that describe a *use* rather than the artefact. These are resolved
# from the discovery source instead, because the same kind means different
# things in different places: a `crypto_api` hit is source code in a .py file
# and a binary in a .so, and typing it by kind alone silently mislabels every
# non-source scanner's output.
_USE_KINDS = frozenset({"algorithm", "crypto_api", "crypto_configuration", "protocol"})

_SOURCE_TYPE_TO_ASSET_TYPE = {
    ScanJob.SourceType.SOURCE_CODE: CryptoAsset.AssetType.SOURCE_CODE,
    ScanJob.SourceType.BINARY: CryptoAsset.AssetType.BINARY,
    ScanJob.SourceType.CONTAINER: CryptoAsset.AssetType.CONTAINER,
    ScanJob.SourceType.CERTIFICATE: CryptoAsset.AssetType.CERTIFICATE,
    ScanJob.SourceType.DEPENDENCY: CryptoAsset.AssetType.DEPENDENCY,
    ScanJob.SourceType.HSM: CryptoAsset.AssetType.HARDWARE,
    ScanJob.SourceType.CLOUD: CryptoAsset.AssetType.CLOUD_RESOURCE,
}


def _source_label(source_type: str) -> str:
    """Human label for a source type, without assuming it is a known choice.

    The registry is the source of truth for what exists, so an unrecognised
    value must degrade to a readable label rather than raise and fail the
    whole job.
    """
    if not source_type:
        return ""
    try:
        return ScanJob.SourceType(source_type).label
    except ValueError:
        return str(source_type).replace("_", " ").title()


def asset_type_for(finding: NormalizedFinding, source_type: str) -> str:
    """Best asset type for a finding: its kind when that is decisive, else the source.

    A kind like `crypto_api` describes a use, not a thing, so it resolves
    through the discovery source. A kind like `certificate` names the thing
    itself and is trusted wherever it was found.
    """
    kind = str(
        (finding.raw_finding.raw_json or {}).get("kind") or "algorithm"
    ).lower()
    decisive = _KIND_TO_ASSET_TYPE.get(kind)
    if decisive:
        return decisive
    if kind in _USE_KINDS:
        return _SOURCE_TYPE_TO_ASSET_TYPE.get(source_type, CryptoAsset.AssetType.UNKNOWN)
    return _SOURCE_TYPE_TO_ASSET_TYPE.get(source_type, CryptoAsset.AssetType.UNKNOWN)


def asset_name(norm: NormalizedFinding, asset_type: str, source_type: str) -> str:
    """A readable identity for the asset, not a derived algorithm string.

    The previous name was ``"RSA 2048 - Source Code Repos"``, which described
    the algorithm rather than the thing, so two different applications using
    RSA produced the same "asset" and neither was distinguishable.
    """
    location = norm.raw_finding.location or ""
    subject = location.split("/")[0] if "/" in location else ""
    algo = norm.algorithm or norm.family or "unknown"

    if asset_type == CryptoAsset.AssetType.CERTIFICATE:
        evidence = (norm.evidence or {})
        subject = str(evidence.get("subject") or subject or "certificate")
    elif asset_type == CryptoAsset.AssetType.KEY_REFERENCE:
        subject = subject or norm.library or "key reference"
    elif asset_type in (CryptoAsset.AssetType.SOURCE_CODE, CryptoAsset.AssetType.APPLICATION):
        subject = subject or "workspace"

    if asset_type in (
        CryptoAsset.AssetType.CERTIFICATE,
        CryptoAsset.AssetType.KEY_REFERENCE,
    ):
        return f"{subject} [{algo}]"[:256]

    scope = subject or _source_label(source_type) or "workspace"
    return f"{scope} — {algo}"[:256]


def asset_identifier(name: str, asset_type: str, norm: NormalizedFinding) -> str:
    """Stable identity for an artefact, derived from its own properties.

    Content-derived so the same artefact keeps one identity across scans while
    two genuinely different things do not collide. Deliberately excludes
    location (identity must survive a move) and library/protocol, which
    discovery may only learn on a later sighting -- including them would split
    one artefact into two the moment a better observation arrived.
    """
    parts = [
        asset_type,
        name,
        norm.algorithm or "",
        str(norm.key_size or ""),
        norm.curve or "",
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:32]


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


def classify_asset(norm: NormalizedFinding, using=None, session_id=None) -> CryptoAsset | None:
    """Create or refresh the canonical CryptoAsset for a normalized finding.

    `session_id` scopes the created asset to a work session. The lookup is on
    (identity, session) rather than name alone, so two workspaces cannot share
    an asset, and a later sighting with better metadata updates the record
    instead of being dropped.

    Bare keywords (crypto, KEY, TLS, HASH, openssl_conf, etc.) are filtered
    out and never become canonical CryptoAsset rows.
    """
    if norm is None:
        return None

    # Filter out bare indicators
    from .normalizer import is_bare_indicator
    if (norm.evidence and norm.evidence.get("is_indicator")) or is_bare_indicator(norm.algorithm, norm.family, norm.kind):
        return None

    if session_id is None:
        session_id = norm.session_id

    location = norm.raw_finding.location
    # Kept alongside the display label so a later stage can relate this asset to
    # a manifest on disk; the label alone is a profile string in a broad scan.
    source_path = norm.raw_finding.source_path or ""
    source_type = norm.raw_finding.source_type
    db = using or norm._state.db or "default"

    asset_type = asset_type_for(norm, source_type)
    name = asset_name(norm, asset_type, source_type)
    identifier = asset_identifier(name, asset_type, norm)

    asset, created = CryptoAsset.objects.using(db).get_or_create(
        session_id=session_id,
        identifier=identifier,
        defaults={
            "name": name,
            "asset_type": asset_type,
            "family": norm.family,
            "algorithm": norm.algorithm,
            "key_size": norm.key_size,
            "curve": norm.curve,
            "protocol": norm.protocol,
            "library": norm.library,
            "library_version": norm.library_version,
            "source_type": source_type,
            "location": location,
            "source_path": source_path,
            "owner": _infer_owner(location),
            "environment": "internet-facing" if (
                (norm.evidence or {}).get("public_endpoint")
                or (norm.evidence or {}).get("internet_facing")
                or "internet" in str((norm.evidence or {}).get("exposure") or "").lower()
            ) else "",
        },
    )

    if created:
        log_action("system", f"Created crypto asset {name}", "cryptoasset", asset.pk, session_id=session_id)
    else:
        # Fill in detail a previous sighting did not have, without overwriting
        # good data with blanks.
        updates = {}
        for field, value in (
            ("curve", norm.curve),
            ("protocol", norm.protocol),
            ("library", norm.library),
            ("library_version", norm.library_version),
            ("key_size", norm.key_size),
            ("source_path", source_path),
        ):
            if value and not getattr(asset, field):
                updates[field] = value
        ev = norm.evidence or {}
        if (ev.get("public_endpoint") or ev.get("internet_facing") or "internet" in str(ev.get("exposure") or "").lower()) and not asset.environment:
            updates["environment"] = "internet-facing"
        if updates:
            for field, value in updates.items():
                setattr(asset, field, value)
            asset.save(using=db, update_fields=list(updates))

    # Every sighting is recorded, including repeats: the second time the same
    # artefact is seen is evidence, not a duplicate to be discarded.
    AssetOccurrence.objects.using(db).update_or_create(
        asset=asset,
        finding=norm,
        defaults={
            "scan_job_id": norm.raw_finding.scan_job_id,
            "location": location,
            "line": norm.line,
            "evidence": norm.evidence or {},
        },
    )

    asset.normalized_findings.add(norm)
    return asset
