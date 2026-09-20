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

    quantum_vuln = risk_counts["vulnerable"] + risk_counts["weak"]
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

    payload = {
        "kpis": {
            "assets": total,
            "quantum_vuln": quantum_vuln,
            "quantum_vuln_pct": _pct(quantum_vuln, total),
            "weak": risk_counts["weak"],
            "pqc_ready": risk_counts["pqc"],
            "pqc_ready_pct": _pct(risk_counts["pqc"], total),
            "scans": scope(ScanJob.objects.all(), sid).count(),
            "analysed": completed_runs.count(),
            "mitigation_assets": mitigation_assets,
            "plan_count": len(plans),
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
    ``vulnerable / weak / moderate / pqc / unknown``. Classical asymmetric
    crypto (RSA/DSA/DH/ECC) breaks under Shor's algorithm regardless of key
    size; weak hashes (MD5/SHA-1) are already broken; symmetric crypto is only
    downgraded by Grover's search.
    """
    family = asset.family
    algo = (asset.algorithm or "").lower().replace("-", "").replace("_", "")
    if family == NormalizedFinding.AlgorithmFamily.PQC:
        return ("pqc", "PQC-ready", "green")
    if family in (
        NormalizedFinding.AlgorithmFamily.RSA,
        NormalizedFinding.AlgorithmFamily.DSA,
        NormalizedFinding.AlgorithmFamily.DH,
        NormalizedFinding.AlgorithmFamily.ECC,
    ):
        return ("vulnerable", "Vulnerable", "red")
    if family == NormalizedFinding.AlgorithmFamily.HASH:
        if algo in ("md5", "sha1"):
            return ("weak", "Weak", "red")
        return ("moderate", "Moderate", "amber")
    if family in (
        NormalizedFinding.AlgorithmFamily.AES,
        NormalizedFinding.AlgorithmFamily.MAC,
    ):
        return ("moderate", "Moderate", "amber")
    return ("unknown", "Unknown", "gray")


def _priority_score(asset: CryptoAsset, risk_key: str) -> int:
    """Deterministic urgency score for ranking vulnerable assets."""
    score = 0
    if risk_key in ("vulnerable", "weak"):
        score += 4
    elif risk_key == "moderate":
        score += 1

    bits = asset.key_size
    if bits:
        if asset.family in ("rsa", "dh", "dsa") and bits < 2048:
            score += 2
        elif asset.family == "ecc" and bits < 256:
            score += 1
    return score


def _pqc_replacement(asset: CryptoAsset) -> str:
    """Suggested PQC / hardening replacement for an asset's algorithm."""
    family = asset.family
    algo = (asset.algorithm or "").lower().replace("-", "").replace("_", "")
    if family == NormalizedFinding.AlgorithmFamily.RSA:
        return "ML-KEM (key exchange) / ML-DSA (signature)"
    if family in (
        NormalizedFinding.AlgorithmFamily.DSA,
        NormalizedFinding.AlgorithmFamily.DH,
    ):
        return "ML-KEM / ML-DSA"
    if family == NormalizedFinding.AlgorithmFamily.ECC:
        return "Hybrid X25519 + ML-KEM / ML-DSA"
    if family == NormalizedFinding.AlgorithmFamily.AES:
        return "AES-256-GCM (Grover headroom)"
    if family == NormalizedFinding.AlgorithmFamily.HASH:
        return "SHA-256 / SHA-3" if algo in ("md5", "sha1") else "SHA-3 (optional)"
    if family == NormalizedFinding.AlgorithmFamily.MAC:
        return "HMAC-SHA-256 / KMAC"
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
            done=total > 0 or analysis_done,
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