"""Dashboard views (server-rendered pages + HTMX partials)."""

from django.db.models import Count
from django.shortcuts import render
from django.views.decorators.http import require_GET

from core.models import AuditLog
from discovery.models import CryptoAsset, NormalizedFinding, RawFinding, ScanJob


def _base_context():
    return {
        "audit_recent": AuditLog.objects.order_by("-created_at")[:10],
        "scan_running": ScanJob.objects.filter(
            status__in=[ScanJob.Status.QUEUED, ScanJob.Status.RUNNING]
        ).count(),
    }


@require_GET
def overview(request):
    assets = list(CryptoAsset.objects.all())
    risk = [_asset_risk(a) for a in assets]

    risk_counts = {"vulnerable": 0, "weak": 0, "moderate": 0, "pqc": 0, "unknown": 0}
    for key, _label, _badge in risk:
        risk_counts[key] += 1

    quantum_vuln = risk_counts["vulnerable"] + risk_counts["weak"]
    total = len(assets)

    vuln_priorities = _vulnerable_priorities(assets, risk)

    ctx = _base_context()
    ctx.update(
        {
            "active": "overview",
            "kpi": {
                "assets": total,
                "quantum_vuln": quantum_vuln,
                "quantum_vuln_pct": _pct(quantum_vuln, total),
                "weak": risk_counts["weak"],
                "pqc_ready": risk_counts["pqc"],
                "pqc_ready_pct": _pct(risk_counts["pqc"], total),
                "scans": ScanJob.objects.count(),
            },
            "workflow": _pqc_workflow(total, risk_counts, vuln_priorities),
            "asset_by_family": _group(CryptoAsset.objects, "family"),
            "risk_split": [
                {"key": "vulnerable", "label": "Vulnerable", "count": risk_counts["vulnerable"]},
                {"key": "weak", "label": "Weak", "count": risk_counts["weak"]},
                {"key": "moderate", "label": "Moderate", "count": risk_counts["moderate"]},
                {"key": "pqc", "label": "PQC-ready", "count": risk_counts["pqc"]},
                {"key": "unknown", "label": "Unknown", "count": risk_counts["unknown"]},
            ],
            "vuln_priorities": vuln_priorities,
            "scans": ScanJob.objects.order_by("-created_at")[:6],
        }
    )
    return render(request, "dashboard/overview.html", ctx)


@require_GET
def discovery(request):
    ctx = _base_context()
    ctx.update(
        {
            "active": "discovery",
            "pipeline": _pipeline_status(),
        }
    )
    return render(request, "dashboard/discovery.html", ctx)


@require_GET
def inventory(request):
    ctx = _base_context()
    ctx.update(
        {
            "active": "inventory",
            "assets": CryptoAsset.objects.order_by("name"),
            "raw_findings": RawFinding.objects.order_by("-ingested_at")[:50],
            "scanjobs": ScanJob.objects.order_by("-created_at")[:20],
        }
    )
    return render(request, "dashboard/inventory.html", ctx)


@require_GET
def asset_graph(request):
    ctx = _base_context()
    ctx.update(
        {
            "active": "graph",
            "assets": CryptoAsset.objects.all(),
            "focus_asset": request.GET.get("asset"),
        }
    )
    return render(request, "dashboard/asset_graph.html", ctx)


@require_GET
def audit_log(request):
    ctx = _base_context()
    ctx.update(
        {
            "active": "audit",
            "audit": AuditLog.objects.select_related("actor").order_by("-created_at")[:200],
        }
    )
    return render(request, "dashboard/audit_log.html", ctx)


@require_GET
def placeholder(request, key):
    titles = {
        "risk": ("Risk & Reasoning", "Risk assessment and reasoning for the assets in your inventory."),
        "mitigation": ("Mitigation", "Remediation guidance and mitigation plans."),
        "reports": ("Reports", "Exportable reports and summaries."),
    }
    title, desc = titles.get(key, (key.title(), ""))
    ctx = _base_context()
    ctx.update({"active": key, "page_key": key, "page_title": title, "page_desc": desc})
    return render(request, "dashboard/placeholder.html", ctx)


def _group(qs, field):
    return list(qs.values(field).annotate(count=Count("id")).order_by("-count"))


def _pipeline_status() -> list[dict]:
    """Abstraction of the discovery pipeline with live counts per stage."""
    raw = RawFinding.objects.count()
    normalized = NormalizedFinding.objects.count()
    assets = CryptoAsset.objects.count()
    relations = CryptoAsset.objects.aggregate(total=Count("outgoing_relations"))["total"] or 0
    scans = ScanJob.objects.count()

    artefacts_by_source = dict(
        CryptoAsset.objects.values_list("source_type")
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
                "asset": asset,
                "score": _priority_score(asset, _key),
                "risk_label": label,
                "risk_badge": badge,
                "replacement": _pqc_replacement(asset),
            }
        )
    rows.sort(key=lambda r: (-r["score"], r["asset"].name))
    return rows


def _pqc_workflow(total: int, risk_counts: dict, vuln_priorities: list[dict]) -> list[dict]:
    """The PQC readiness workflow shown on the overview page.

    Mirrors the MVP: discover -> assess quantum risk -> prioritize ->
    migrate (PQC) -> CBOM output. Future segments render as pending steps.
    """
    def stage(name, key, count, detail, done, sub=None):
        return {
            "name": name,
            "key": key,
            "count": count,
            "detail": detail,
            "done": done,
            "sub": sub or [],
        }

    return [
        stage(
            "Scan / Discover",
            "discover",
            total,
            "intake repos, binaries, containers, certs, HSM, cloud",
            done=total > 0,
        ),
        stage(
            "Assess Quantum Risk",
            "assess",
            risk_counts["vulnerable"] + risk_counts["weak"] + risk_counts["moderate"],
            "Shor / Grover exposure · Mosca: data lifetime + migration vs horizon",
            done=total > 0,
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
        ),
        stage(
            "PQC Migration",
            "migrate",
            0,
            "hybrid + pure PQC (ML-KEM / ML-DSA) — Segment C",
            done=False,
        ),
        stage(
            "CBOM Report",
            "cbom",
            0,
            "CycloneDX crypto bill of materials — deferred",
            done=False,
        ),
    ]
