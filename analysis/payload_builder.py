"""CBOM-ready payload adapter (analysis).

Simultaneously holds the Discovery inventory asset graph and turns it into the
flat finding list that CBOMAgent consumes. This module only adapts already
discovered/normalized/classified data; it does NOT classify or enrich anything.
The actual classification/enrichment happens downstream in the CBOM agent
(CBOMAgent.process) and the Risk Classification agent
(RiskClassificationAgent). This module only reads the discovery models and
returns plain dicts, so it stays decoupled from the (parallel) analysis.models.
"""

from typing import Any, Dict, Optional

from discovery.models import CryptoAsset, NormalizedFinding, RawFinding, ScanJob


def finding_id_for(normalized: NormalizedFinding) -> str:
    """Return a stable string id for a normalized finding, e.g. 'N12'."""
    if normalized.pk is None:
        return "N-1"
    return f"N{normalized.pk}"


def finding_from_raw(
    raw: RawFinding, normalized: Optional[NormalizedFinding] = None
) -> Dict[str, Any]:
    """Convert one RawFinding into a CBOM-ready pipeline 'finding' dict."""
    data = raw.raw_json or {}
    norm = normalized if normalized is not None else None
    algorithm = str(data.get("algorithm") or "crypto")
    location_val = str(data.get("location") or raw.location or "")

    match = data.get("raw") or {}
    strings = match.get("strings") if isinstance(match, dict) else None
    if isinstance(strings, list) and strings:
        code = "; ".join(str(s) for s in strings[:3])
    else:
        code = f"{algorithm} artefact detected in {location_val}"

    finding = {
        "id": finding_id_for(norm) if norm else "N-1",
        "file": location_val,
        "line": None,
        "detected": data.get("algorithm") or "unknown",
        "code": code,
        "family": str(data.get("family") or ""),
        "confidence": data.get("confidence", 0.6),
        "protocol": data.get("protocol") or (norm.protocol if norm else "") or "",
        "parameters": {
            "key_size": (getattr(norm, "key_size", None) if norm else None),
            "curve": ((getattr(norm, "curve", "") or "") if norm else ""),
        },
    }

    if "key_size" in data:
        finding["key_size"] = data["key_size"]
    if "curve" in data:
        finding["curve"] = data["curve"]

    return finding


def build_analysis_payload(scan_job: ScanJob, max_findings: int = 500) -> Dict[str, Any]:
    """Build a CBOM-ready payload for all findings linked to a ScanJob."""
    max_findings = max(0, int(max_findings))
    db = scan_job._state.db or "default"

    norm_ids = (
        NormalizedFinding.objects.using(db)
        .filter(raw_finding__scan_job=scan_job)
        .values_list("id", flat=True)
    )
    if scan_job.session_id:
        norm_ids = norm_ids.filter(session_id=scan_job.session_id)

    assets = (
        CryptoAsset.objects.using(db)
        .filter(normalized_findings__id__in=norm_ids)
        .distinct()
        .prefetch_related("normalized_findings", "normalized_findings__raw_finding")
    )
    if scan_job.session_id:
        assets = assets.filter(session_id=scan_job.session_id)

    findings = []
    seen = set()
    scan_id = scan_job.id

    for asset in assets:
        for norm in asset.normalized_findings.all():
            if not norm or norm.raw_finding.scan_job_id != scan_id:
                continue
            finding = finding_from_raw(norm.raw_finding, norm)
            dedup_key = (finding["id"], finding["file"], finding["detected"])
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            findings.append(finding)
            if len(findings) >= max_findings:
                return _payload(scan_job, findings)

    return _payload(scan_job, findings)


def default_raw_system_context(
    scan_job: Optional[ScanJob] = None,
) -> Dict[str, Any]:
    """Conservative default input for RiskClassificationAgent.analyze."""
    name = scan_job.target if (scan_job and scan_job.target) else "ECDAT inventory"
    return {
        "application": {
            "name": name,
            "type": "internal_system",
            "description": "Cryptographic assets discovered on an internal system.",
        },
        "data": {
            "types": ["internal_operational_logs"],
            "description": "Configuration, keys, certificates and code derived from the host.",
        },
        "network": {
            "publicly_accessible": False,
            "internet_facing": False,
            "external_users": False,
        },
        "business_context": {
            "data_retention_years": 5,
            "long_term_value": False,
        },
    }


def parse_finding_id(finding_id: str) -> Optional[int]:
    """Parse a finding id like 'N12' back to the raw integer (12), else None."""
    s = str(finding_id or "")
    if not s.startswith("N"):
        return None
    digits = s[1:]
    if not digits.isdigit():
        return None
    return int(digits)


def _payload(scan_job: ScanJob, findings: list) -> Dict[str, Any]:
    return {
        "repository": {
            "name": scan_job.target or f"{scan_job.source_type} scan",
            "url": "",
        },
        "findings": findings,
    }