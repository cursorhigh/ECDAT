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

from segments.scraping.discovery.models import CryptoAsset, NormalizedFinding, RawFinding, ScanJob


def finding_id_for(normalized: NormalizedFinding) -> str:
    """Return a stable string id for a normalized finding, e.g. 'N12'."""
    if normalized.pk is None:
        return "N-1"
    return f"N{normalized.pk}"


def finding_from_raw(
    raw: Optional[RawFinding] = None, normalized: Optional[NormalizedFinding] = None
) -> Dict[str, Any]:
    """Convert a finding into a CBOM-ready pipeline 'finding' dict."""
    data = raw.raw_json if (raw and raw.raw_json) else {}
    norm = normalized if normalized is not None else None
    algorithm = str((norm.algorithm if norm and norm.algorithm else None) or data.get("algorithm") or "crypto")
    location_val = str((raw.location if raw else "") or data.get("location") or "")

    match = data.get("raw") or {}
    strings = match.get("strings") if isinstance(match, dict) else None
    if isinstance(strings, list) and strings:
        code = "; ".join(str(s) for s in strings[:3])
    else:
        code = f"{algorithm} artefact detected in {location_val}"

    finding = {
        "id": finding_id_for(norm) if norm else "N-1",
        "file": location_val,
        "line": norm.line if norm else None,
        "detected": algorithm,
        "code": code,
        "family": str(norm.family if norm and norm.family else data.get("family") or ""),
        "confidence": float(norm.confidence if norm and norm.confidence is not None else data.get("confidence", 0.6)),
        "protocol": (norm.protocol if norm and norm.protocol else data.get("protocol") or ""),
        "parameters": {
            "key_size": (getattr(norm, "key_size", None) if norm else data.get("key_size")),
            "curve": ((getattr(norm, "curve", "") or "") if norm else data.get("curve", "")),
        },
    }

    if "key_size" in data and finding["parameters"]["key_size"] is None:
        finding["parameters"]["key_size"] = data["key_size"]
    if "curve" in data and not finding["parameters"]["curve"]:
        finding["parameters"]["curve"] = data["curve"]

    return finding


def build_analysis_payload(scan_job: ScanJob, max_findings: int | None = None) -> Dict[str, Any]:
    """Build a CBOM-ready payload for all findings linked to a ScanJob or its multi-source batch.

    `max_findings=None` means no cap: every deduplicated finding discovered for the
    job is analysed. It must stay distinguishable from 0, which would analyse nothing.
    """
    if max_findings is not None:
        max_findings = max(0, int(max_findings))
    db = scan_job._state.db or "default"

    # 1. First, search for NormalizedFindings for this specific scan job
    norm_qs = (
        NormalizedFinding.objects.using(db)
        .filter(raw_finding__scan_job=scan_job)
        .select_related("raw_finding")
    )

    # 2. If this specific scanner returned 0 findings (e.g. binary scanner in a multi-source folder scan),
    # aggregate findings from the parent batch or same session and target
    if not norm_qs.exists() and getattr(scan_job, "batch_id", None):
        norm_qs = (
            NormalizedFinding.objects.using(db)
            .filter(raw_finding__scan_job__batch_id=scan_job.batch_id)
            .select_related("raw_finding")
        )
    elif not norm_qs.exists() and scan_job.session_id and scan_job.target:
        norm_qs = (
            NormalizedFinding.objects.using(db)
            .filter(session_id=scan_job.session_id, raw_finding__scan_job__target=scan_job.target)
            .select_related("raw_finding")
        )

    findings = []
    seen = set()

    for norm in norm_qs:
        finding = finding_from_raw(norm.raw_finding, norm)
        dedup_key = (finding["id"], finding["file"], finding["detected"])
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        findings.append(finding)

    total_available = len(findings)
    if max_findings is not None and total_available > max_findings:
        findings = findings[:max_findings]

    return _payload(scan_job, findings, total_available, max_findings)


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


def _payload(
    scan_job: ScanJob,
    findings: list,
    total_available: int | None = None,
    max_findings: int | None = None,
) -> Dict[str, Any]:
    """Build the analysis payload, recording any truncation explicitly.

    A capped payload must never look like a complete one: every count derived
    downstream (summary rows, plan coverage, reports) is only as complete as
    this list, so the shortfall is reported rather than hidden.
    """
    available = len(findings) if total_available is None else total_available
    # A payload is truncated only when findings were actually dropped. Comparing
    # `len(findings) >= max_findings` as well would flag a run that happened to
    # land exactly on the limit (available == limit) as truncated, showing a
    # false "analysed N of N" shortfall banner for a run that lost nothing.
    truncated = max_findings is not None and available > len(findings)
    payload: Dict[str, Any] = {
        "repository": {
            "name": scan_job.target or f"{scan_job.source_type} scan",
            "url": "",
        },
        "findings": findings,
    }
    if truncated:
        payload["truncation"] = {
            "truncated": True,
            "analysed": len(findings),
            "available": available,
            "limit": max_findings,
        }
    return payload