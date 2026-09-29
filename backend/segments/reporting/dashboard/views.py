"""Estate-metrics API for the reporting segment.

ECDAT is a backend-only API service: the server-rendered pages were removed,
and the queries that powered them survive here as JSON endpoints so a
front-end can rebuild the same PQC-readiness view:

    GET /api/reporting/overview/   estate KPIs, risk split, PQC workflow
    GET /api/reporting/pipeline/   discovery pipeline stage counts
    GET /api/reporting/audit/      recent audit-log entries
"""

from django.db.models import Count
from django.http import JsonResponse
from django.views.decorators.http import require_GET

from core.models import AuditLog
from core.modes import active_db
from core.sessions import scope, thread_session_id
from segments.ml.analysis.models import AnalysisRun, AssetAssessment
from segments.scraping.discovery.models import CryptoAsset, NormalizedFinding, RawFinding, ScanJob
from segments.mitigation.mitigation.models import MitigationPlan


def _sid():
    """Active work-session pk (None = "All data" / no scoping)."""
    return thread_session_id() or None


_PRIORITY_RANK = {"URGENT": 0, "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _priority_rank(value):
    """Rank a migration-priority / overall-risk label (lower = more urgent)."""
    if not value:
        return 99
    return _PRIORITY_RANK.get(str(value).upper(), 50)


@require_GET
def overview(request):
    sid = _sid()
    assets = list(scope(CryptoAsset.objects.all(), sid))
    risk = [_asset_risk(a) for a in assets]

    risk_counts = {"vulnerable": 0, "weak": 0, "moderate": 0, "pqc": 0, "unknown": 0}
    for key, _label, _badge in risk:
        risk_counts[key] += 1

    quantum_vuln = risk_counts["vulnerable"]
    weak_count = risk_counts["weak"]
    total = len(assets)

    vuln_priorities = _vulnerable_priorities(assets, risk)

    completed_runs = _completed_runs()
    analysis_assets = _analysis_assets(completed_runs)

    plans = list(
        scope(MitigationPlan.objects.using(active_db()).all(), sid)
        .filter(status=MitigationPlan.Status.COMPLETE)
        .order_by("-created_at")
    )
    mitigation_assets = sum(
        ((p.document or {}).get("summary") or {}).get("assets", 0) for p in plans
    )

    # --- headline numbers, chosen for what an executive can act on ----------
    #
    # A scan is one session that fans out into one job per source, so counting
    # ScanJob rows and calling it "discovery runs" reported the width of the
    # scan, not the number of scans. Sources and findings are what that count
    # actually meant, and they are what an executive should read.
    scan_jobs = list(
        scope(ScanJob.objects.all(), sid).values_list(
            "source_type", "status", "items_total", "items_scanned"
        )
    )
    sources_scanned = len({row[0] for row in scan_jobs})
    raw_findings = scope(RawFinding.objects.all(), sid).count()

    # Coverage is aggregated across the session's jobs. Sources that do not
    # report a total (certificates, containers) contribute nothing rather than
    # being counted as fully read, so this cannot overstate what was inspected.
    reported_total = sum(row[2] for row in scan_jobs if row[2])
    items_scanned = sum(row[3] or 0 for row in scan_jobs if row[2])

    # Risk conclusions live in the assessment JSON, not on the asset row.
    # SQLite evaluates these as json_extract, so the counts are aggregated by
    # the database rather than by walking rows in Python.
    assessments = scope(AssetAssessment.objects.using(active_db()).all(), sid)
    assessed = assessments.count()
    flagged = assessments.filter(
        mosca_result__mosca_assessment__migration_priority__in=["URGENT", "HIGH"]
    )
    needs_migration = flagged.count()
    # The flagged count is per finding, so one asset used in 47 places counts 47
    # times. "How many things must I actually fix" is the number of distinct
    # assets, which is far smaller -- and is the one an executive can act on.
    needs_migration_assets = scope(CryptoAsset.objects.all(), sid).filter(
        id__in=flagged.exclude(asset=None).values("asset_id")
    ).count()
    hndl_exposed = assessments.filter(
        hndl_result__hndl__future_decryption_risk__in=["MEDIUM", "HIGH", "CRITICAL"]
    ).count()
    hndl_exposed_assets = scope(CryptoAsset.objects.all(), sid).filter(
        id__in=assessments.filter(
            hndl_result__hndl__future_decryption_risk__in=["MEDIUM", "HIGH", "CRITICAL"]
        )
        .exclude(asset=None)
        .values("asset_id")
    ).count()
    # Surfaced rather than hidden: a product that quietly drops what it could
    # not assess is overstating its own coverage.
    not_assessable = assessments.filter(
        hndl_result__hndl__future_decryption_risk="NOT_ASSESSABLE"
    ).count()
    # Findings collapse into far fewer distinct assets, so the two are reported
    # together. Presenting either alone invites a wrong order of magnitude.
    raw_findings_in_scope = raw_findings

    payload = {
        "kpis": {
            "assets": total,
            "quantum_vuln": quantum_vuln,
            "quantum_vuln_pct": _pct(quantum_vuln, total),
            "weak": risk_counts["weak"],
            "pqc_ready": risk_counts["pqc"],
            "pqc_ready_pct": _pct(risk_counts["pqc"], total),
            "scans": len(scan_jobs),
            "analysed": completed_runs.count(),
            "mitigation_assets": mitigation_assets,
            "plan_count": len(plans),
            "sources_scanned": sources_scanned,
            "findings": raw_findings_in_scope,
            "needs_migration": needs_migration,
            "needs_migration_pct": _pct(needs_migration, assessed),
            "needs_migration_assets": needs_migration_assets,
            "hndl_exposed": hndl_exposed,
            "hndl_exposed_pct": _pct(hndl_exposed, assessed),
            "hndl_exposed_assets": hndl_exposed_assets,
            "assessed": assessed,
            "not_assessable": not_assessable,
            "not_assessable_pct": _pct(not_assessable, assessed),
            "coverage_pct": _pct(items_scanned, reported_total),
            "items_total": reported_total,
            "items_scanned": items_scanned,
        },
        "analysis_done": completed_runs.exists(),
        "analysis_assets": analysis_assets,
        "mitigation_done": bool(plans),
        "scan_running": scope(ScanJob.objects.all(), sid)
        .filter(status__in=[ScanJob.Status.QUEUED, ScanJob.Status.RUNNING])
        .count(),
        "analysis_running": scope(AnalysisRun.objects.all(), sid)
        .filter(status__in=[AnalysisRun.Status.QUEUED, AnalysisRun.Status.RUNNING])
        .count(),
        "workflow": _pqc_workflow(
            total,
            risk_counts,
            vuln_priorities,
            analysis_done=completed_runs.exists(),
            analysis_assets=analysis_assets,
            mitigation_done=bool(plans),
            mitigation_assets=mitigation_assets,
        ),
        "asset_by_family": _group(scope(CryptoAsset.objects.all(), sid), "family"),
        "risk_split": [
            {"key": "vulnerable", "label": "Vulnerable", "count": risk_counts["vulnerable"]},
            {"key": "weak", "label": "Weak", "count": risk_counts["weak"]},
            {"key": "moderate", "label": "Moderate", "count": risk_counts["moderate"]},
            {"key": "pqc", "label": "PQC-ready", "count": risk_counts["pqc"]},
            {"key": "unknown", "label": "Unknown", "count": risk_counts["unknown"]},
        ],
        "vuln_priorities": vuln_priorities,
        "recent_scans": list(
            scope(ScanJob.objects.all(), sid)
            .order_by("-created_at")[:6]
            .values("id", "target", "source_type", "status", "created_at")
        ),
    }
    return JsonResponse(payload)


@require_GET
def pipeline(request):
    """Discovery pipeline with live counts per stage (GET /api/reporting/pipeline/)."""
    return JsonResponse({"stages": _pipeline_status()})


@require_GET
def audit(request):
    """Recent audit-log entries (GET /api/reporting/audit/?limit=200)."""
    try:
        limit = min(1000, max(1, int(request.GET.get("limit", 200))))
    except (TypeError, ValueError):
        limit = 200
    sid = _sid()
    rows = (
        scope(AuditLog.objects.all(), sid)
        .select_related("actor")
        .order_by("-created_at")[:limit]
    )
    return JsonResponse(
        {
            "count": len(list(rows)),
            "entries": [
                {
                    "id": e.pk,
                    "action": e.action,
                    "message": e.message,
                    "target_type": e.target_type,
                    "target_id": e.target_id,
                    "actor": e.actor.username if e.actor else None,
                    "session_id": e.session_id,
                    "created_at": e.created_at,
                }
                for e in rows
            ],
        }
    )


def _group(qs, field):
    return list(qs.values(field).annotate(count=Count("id")).order_by("-count"))


def _completed_runs():
    return (
        scope(AnalysisRun.objects.using(active_db()).all(), _sid())
        .filter(status=AnalysisRun.Status.COMPLETED)
    )


def _analysis_assets(completed_runs):
    completed_runs = list(completed_runs)
    if not completed_runs:
        return 0
    latest = completed_runs[0]
    stats = (latest.executive_summary or {}).get("stats") or {}
    if stats.get("assets"):
        return stats["assets"]
    return (
        scope(AssetAssessment.objects.using(active_db()).all(), _sid())
        .filter(run=latest)
        .count()
    )


def _pipeline_status() -> list[dict]:
    """Abstraction of the discovery pipeline with live counts per stage."""
    sid = _sid()
    raw = scope(RawFinding.objects.all(), sid).count()
    normalized = scope(NormalizedFinding.objects.all(), sid).count()
    assets_qs = scope(CryptoAsset.objects.all(), sid)
    assets = assets_qs.count()
    relations = assets_qs.aggregate(total=Count("outgoing_relations"))["total"] or 0
    scans = scope(ScanJob.objects.all(), sid).count()

    artefacts_by_source = dict(
        assets_qs.values_list("source_type")
        .annotate(n=Count("id"))
        .values_list("source_type", "n")
    )
    source_labels = dict(ScanJob.SourceType.choices)
    artefact_sub = [
        {"label": source_labels.get(k, k), "count": v}
        for k, v in artefacts_by_source.items()
    ]

    def stage(name, key, count, detail, sub=None):
        return {
            "name": name,
            "key": key,
            "count": count,
            "detail": detail,
            "sub": sub or [],
            "done": count > 0,
        }

    return [
        stage("Scan", "scan", scans, "scanner run against a target"),
        stage("Intake", "raw", raw, "raw findings persisted"),
        stage("Normalize", "norm", normalized, "dedup + canonical fields"),
        stage(
            "Identify Artefacts",
            "asset",
            assets,
            "algorithms · keys · certificates · protocols · libraries · HW modules · cloud services",
            sub=artefact_sub,
        ),
        stage("Correlate", "graph", relations, "link artefacts with surrounding data and context"),
    ]


def _pct(part: int, total: int) -> int:
    """Percent of `part` within `total`, rounded (0 when total is empty)."""
    return round(100 * part / total) if total else 0


def _asset_public(asset: CryptoAsset) -> dict:
    """Stable public representation of a crypto asset."""
    return {
        "id": asset.pk,
        "name": asset.name,
        "family": asset.family,
        "algorithm": asset.algorithm,
        "key_size": asset.key_size,
        "curve": asset.curve,
        "protocol": asset.protocol,
        "library": asset.library,
        "source_type": asset.source_type,
        "location": asset.location,
        "owner": asset.owner,
        "inventory_status": asset.inventory_status,
    }


def _asset_risk(asset: CryptoAsset) -> tuple[str, str, str]:
    """Classify an asset's quantum-readiness from its canonical fields.

    Returns ``(risk_key, label, badge)`` where risk_key is one of
    ``vulnerable / weak / moderate / pqc / unknown``.
    - vulnerable: Classical asymmetric crypto (RSA/DSA/DH/ECC) vulnerable to Shor's algorithm.
    - weak: Classically broken or deprecated primitives (MD5, SHA-1, DES, 3DES, RC4, Blowfish, RC2).
    - moderate: Quantum-resilient symmetric/hash primitives evaluated for Grover safety margins or legacy review.
    - pqc: Approved post-quantum mechanisms (ML-KEM, ML-DSA, SLH-DSA).
    """
    family = str(getattr(asset, "family", "") or "").lower()
    algo = str(getattr(asset, "algorithm", "") or "").lower().replace("-", "").replace("_", "")
    name = str(getattr(asset, "name", "") or "").lower()
    role = str(getattr(asset, "role", "") or "").lower()

    if family == NormalizedFinding.AlgorithmFamily.PQC or "mlkem" in algo or "mldsa" in algo or "slhdsa" in algo:
        return ("pqc", "PQC-ready", "green")
    if family in (
        NormalizedFinding.AlgorithmFamily.RSA,
        NormalizedFinding.AlgorithmFamily.DSA,
        NormalizedFinding.AlgorithmFamily.DH,
        NormalizedFinding.AlgorithmFamily.ECC,
        "rsa", "dsa", "dh", "ecc",
    ) or any(k in algo for k in ["rsa", "ecdsa", "ecdh", "ed25519", "x25519", "dsa", "dh"]):
        return ("vulnerable", "Vulnerable (Shor)", "red")
    if any(k in algo for k in ["des", "3des", "desede", "rc4", "rc2", "blowfish"]):
        return ("weak", "Weak (Classical)", "red")
    if "hmacsha1" in algo or "hmac-sha1" in algo or "hmac-sha-1" in algo:
        return ("moderate", "Legacy - Review", "amber")
    if "md5" in algo or "sha1" in algo or algo == "sha1":
        if role in ("checksum", "file_checksum", "non_security", "nonsecurity"):
            return ("moderate", "Checksum / Non-Security", "amber")
        return ("weak", "Weak (Classical)", "red")
    if family in (NormalizedFinding.AlgorithmFamily.HASH, "hash"):
        return ("moderate", "Moderate (Grover Margin)", "amber")
    if family in (
        NormalizedFinding.AlgorithmFamily.AES,
        NormalizedFinding.AlgorithmFamily.MAC,
        "aes", "mac", "symmetric",
    ) or any(k in algo for k in ["aes", "chacha", "camellia", "hmac"]):
        return ("moderate", "Moderate (Grover Margin)", "amber")
    return ("unknown", "Unknown", "gray")


NON_SECURITY_HINTS = (
    "checksum",
    "check_sum",
    "non_security",
    "nonsecurity",
    "non-security",
    "fingerprint",
)


def _looks_non_security(asset: CryptoAsset) -> bool:
    """True when the algorithm is very likely used outside a security control.

    There is no ``role`` column on CryptoAsset, so an earlier check of
    ``asset.role`` was silently always false and the downgrade below never
    fired -- every classical-weak hash scored as if it were protecting
    something. The usage context has to be inferred from what does exist: the
    file it was found in and the name it was given.
    """
    haystack = " ".join(
        str(getattr(asset, field, "") or "")
        for field in ("location", "name", "source_path", "identifier")
    ).lower()
    return any(hint in haystack for hint in NON_SECURITY_HINTS)


def _priority_score(asset: CryptoAsset, risk_key: str) -> int:
    """Deterministic urgency score (0-100) for ranking cryptographic assets.

    Weak security-use algorithms receive a floor of 70 (HIGH). Shor-vulnerable
    asymmetric keys start at 80 (HIGH/CRITICAL) and rise with key weakness.

    The ordering matters for a quantum-migration list: anything a CRQC breaks
    must outrank a classical weakness, otherwise MD5-in-a-checksum would be
    presented above the RSA an attacker will actually harvest. That is why the
    weak floor is 70 and not the 85 this function used to return -- the old
    value put every classical-weak asset above every Shor-vulnerable one, and
    contradicted the 70 its own docstring described.
    """
    if risk_key == "vulnerable":
        score = 80
        bits = getattr(asset, "key_size", None)
        family = str(getattr(asset, "family", "") or "").lower()
        if bits:
            if family in ("rsa", "dh", "dsa") and bits < 2048:
                score = 95
            elif family == "ecc" and bits < 256:
                score = 90
        return score
    elif risk_key == "weak":
        if _looks_non_security(asset):
            return 35
        return 70
    elif risk_key == "moderate":
        algo = str(getattr(asset, "algorithm", "") or "").lower()
        if "128" in algo:
            return 45
        if "hmacsha1" in algo:
            return 40
        return 30
    elif risk_key == "pqc":
        return 10
    return 50


def _pqc_replacement(asset: CryptoAsset) -> str:
    """Suggested PQC / hardening replacement for an asset's algorithm and role."""
    family = str(getattr(asset, "family", "") or "").lower()
    algo = str(getattr(asset, "algorithm", "") or "").lower().replace("-", "").replace("_", "")
    name = str(getattr(asset, "name", "") or "").lower()
    role = str(getattr(asset, "role", "") or "").lower()

    if "ecdsa" in algo:
        return "ML-DSA-65 / ML-DSA-87 (FIPS 204) / SLH-DSA"
    if "ed25519" in algo or "eddsa" in algo:
        return "ML-DSA-65 (FIPS 204) / SLH-DSA"
    if "ecdh" in algo:
        return "ML-KEM-768 / ML-KEM-1024 (FIPS 203) / Hybrid X25519MLKEM768"
    if "x25519" in algo or "x448" in algo or family in (NormalizedFinding.AlgorithmFamily.DH, "dh"):
        return "ML-KEM-768 (Hybrid X25519MLKEM768)"

    if family in (NormalizedFinding.AlgorithmFamily.RSA, "rsa") or "rsa" in algo:
        if any(w in role for w in ["enc", "key", "transport", "exchange", "kem", "agreement"]):
            return "ML-KEM-768 / ML-KEM-1024 (FIPS 203)"
        if any(w in role for w in ["sign", "cert", "auth", "verify"]):
            return "ML-DSA-65 / ML-DSA-87 (FIPS 204) / SLH-DSA"
        if any(w in name for w in ["enc", "key", "transport", "exchange", "kem", "agreement"]):
            return "ML-KEM-768 / ML-KEM-1024 (FIPS 203)"
        if any(w in name for w in ["sign", "cert", "auth", "verify"]):
            return "ML-DSA-65 / ML-DSA-87 (FIPS 204) / SLH-DSA"
        return "ML-KEM-768 (Key Exchange) / ML-DSA-65 (Signatures)"

    if family in (NormalizedFinding.AlgorithmFamily.ECC, "ecc") or "ecc" in algo or algo == "ec":
        if any(w in role for w in ["enc", "key", "transport", "exchange", "kem", "agreement"]):
            return "ML-KEM-768 / ML-KEM-1024 (FIPS 203) / Hybrid X25519MLKEM768"
        if any(w in role for w in ["sign", "cert", "auth", "verify"]):
            return "ML-DSA-65 / ML-DSA-87 (FIPS 204) / SLH-DSA"
        if any(w in name for w in ["enc", "key", "transport", "exchange", "kem", "agreement"]):
            return "ML-KEM-768 / ML-KEM-1024 (FIPS 203) / Hybrid X25519MLKEM768"
        if any(w in name for w in ["sign", "cert", "auth", "verify"]):
            return "ML-DSA-65 / ML-DSA-87 (FIPS 204) / SLH-DSA"
        return "ML-KEM-768 (Key Exchange) / ML-DSA-65 (Signatures)"

    if any(k in algo for k in ["des", "3des", "rc4", "rc2", "blowfish"]):
        return "AES-256-GCM / ChaCha20-Poly1305"
    if "hmacsha1" in algo or "hmac-sha1" in algo:
        return "HMAC-SHA-256 / KMAC"
    if family in (NormalizedFinding.AlgorithmFamily.AES, "aes", "symmetric") or "aes" in algo or "chacha" in algo:
        key_size = getattr(asset, "key_size", None)
        if key_size and key_size < 256:
            return "AES-256-GCM (Grover 128-bit headroom)"
        return "AES-256-GCM - Retain (Strong)"

    if family in (NormalizedFinding.AlgorithmFamily.HASH, "hash") or any(k in algo for k in ["md5", "sha1", "sha256", "sha384", "sha512", "sha3"]):
        if algo in ("md5", "sha1"):
            return "SHA-256 / SHA-3"
        return "SHA-256 / SHA-3 - Retain (Strong)"

    if family in (NormalizedFinding.AlgorithmFamily.MAC, "mac"):
        return "HMAC-SHA-256 / KMAC - Retain (Strong)"
    return "Reassess after discovery"


def _vulnerable_priorities(assets: list[CryptoAsset], risk: list[tuple]) -> list[dict]:
    """Assets that need PQC attention, ranked by a priority score."""
    rows = []
    for asset, (_key, label, badge) in zip(assets, risk):
        if _key not in ("vulnerable", "weak"):
            continue
        rows.append(
            {
                "asset": _asset_public(asset),
                "score": _priority_score(asset, _key),
                "risk_label": label,
                "risk_badge": badge,
                "replacement": _pqc_replacement(asset),
            }
        )
    rows.sort(key=lambda r: (-r["score"], r["asset"]["name"]))
    return rows


def _pqc_workflow(
    total: int,
    risk_counts: dict,
    vuln_priorities: list[dict],
    analysis_done: bool = False,
    analysis_assets: int = 0,
    mitigation_done: bool = False,
    mitigation_assets: int = 0,
) -> list[dict]:
    """The PQC readiness pipeline shown on the overview page.

    Scan → Assess → Prioritize → Mitigate → Report: every step is both a
    status and a link to its tab, so the workflow always flows onward. A
    step is ``done`` the moment its output exists.
    """

    def stage(name, key, count, detail, done, api, sub=None):
        return {
            "name": name,
            "key": key,
            "count": count,
            "detail": detail,
            "done": done,
            "api": api,
            "sub": sub or [],
        }

    return [
        stage(
            "Scan / Discover",
            "discover",
            total,
            "intake repos, binaries, containers, certs, HSM, cloud",
            done=total > 0,
            api="/api/scans/",
        ),
        stage(
            "Assess Quantum Risk",
            "assess",
            risk_counts["vulnerable"] + risk_counts["weak"] + risk_counts["moderate"],
            "Shor / Grover exposure · Mosca: data lifetime + migration vs horizon",
            # Strictly the analysis run. This used to read `total > 0 or
            # analysis_done`, which marked the stage complete as soon as assets
            # existed -- but assets exist *before* any risk is assessed, so a
            # progress bar built on it would claim a stage it never reached.
            done=analysis_done,
            api="/api/assets/",
            sub=[
                {"label": label, "count": risk_counts[key]}
                for key, label in (
                    ("vulnerable", "vulnerable"),
                    ("weak", "weak"),
                    ("moderate", "moderate"),
                    ("pqc", "pqc-ready"),
                )
                if risk_counts[key]
            ],
        ),
        stage(
            "Prioritize",
            "prioritize",
            len(vuln_priorities),
            "risk, data lifetime, business criticality, migration effort",
            done=bool(vuln_priorities),
            api="/api/analysis/",
        ),
        stage(
            "PQC Mitigation",
            "mitigate",
            mitigation_assets or (1 if mitigation_done else 0),
            "hybrid + pure PQC (ML-KEM / ML-DSA) · auto-run per analysis",
            done=mitigation_done,
            api="/api/mitigation/",
        ),
        stage(
            "Full Report",
            "report",
            1 if mitigation_done else 0,
            "Enterprise PDF report · analysis + mitigation, generated on demand",
            done=mitigation_done and analysis_done,
            api="/api/reports/full.json",
        ),
    ]