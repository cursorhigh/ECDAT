"""Dashboard views (server-rendered pages + HTMX partials)."""

import json

from django.db.models import Count
from django.http import Http404
from django.shortcuts import render
from django.urls import reverse
from django.views.decorators.http import require_GET

from analysis.models import AnalysisRun, AssetAssessment
from analysis.payload_builder import default_raw_system_context
from analysis.views import _load_run
from core.models import AuditLog
from core.modes import active_db, db_alias_for_mode
from core.sessions import scope, thread_session_id
from discovery.models import CryptoAsset, NormalizedFinding, RawFinding, ScanJob
from mitigation.models import MitigationPlan
from mitigation.planner import trigger_mitigation


def _sid():
    """Active work-session pk (None = "All data" / no scoping)."""
    return thread_session_id() or None


_PRIORITY_RANK = {"URGENT": 0, "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _priority_rank(value):
    """Rank a migration-priority / overall-risk label (lower = more urgent)."""
    if not value:
        return 99
    return _PRIORITY_RANK.get(str(value).upper(), 50)


def _base_context():
    sid = _sid()
    return {
        "audit_recent": scope(AuditLog.objects.all(), sid).order_by("-created_at")[:10],
        "audit_count": scope(AuditLog.objects.all(), sid).count(),
        "scan_running": scope(ScanJob.objects.all(), sid)
        .filter(status__in=[ScanJob.Status.QUEUED, ScanJob.Status.RUNNING])
        .count(),
        "analysis_running": scope(AnalysisRun.objects.all(), sid)
        .filter(status__in=[AnalysisRun.Status.QUEUED, AnalysisRun.Status.RUNNING])
        .count(),
    }


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
    mitigation_done = bool(plans)
    mitigation_assets = sum(
        ((p.document or {}).get("summary") or {}).get("assets", 0) for p in plans
    )
    plan_count = len(plans)

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
                "scans": scope(ScanJob.objects.all(), sid).count(),
                "analysed": completed_runs.count(),
            },
            "analysis_done": completed_runs.exists(),
            "analysis_assets": analysis_assets,
            "mitigation_done": mitigation_done,
            "mitigation_assets": mitigation_assets,
            "plan_count": plan_count,
            "workflow": _pqc_workflow(
                total,
                risk_counts,
                vuln_priorities,
                analysis_done=completed_runs.exists(),
                analysis_assets=analysis_assets,
                mitigation_done=mitigation_done,
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
            "scans": scope(ScanJob.objects.all(), sid).order_by("-created_at")[:6],
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
    sid = _sid()
    ctx = _base_context()
    ctx.update(
        {
            "active": "inventory",
            "findings": scope(NormalizedFinding.objects.all(), sid)
            .select_related("raw_finding")
            .order_by("family", "algorithm")[:400],
            "raw_findings": scope(RawFinding.objects.all(), sid).order_by("-ingested_at")[:50],
        }
    )
    return render(request, "dashboard/inventory.html", ctx)


@require_GET
def asset_graph(request):
    sid = _sid()
    ctx = _base_context()
    ctx.update(
        {
            "active": "graph",
            "assets": scope(CryptoAsset.objects.all(), sid),
            "focus_asset": request.GET.get("asset"),
        }
    )
    resp = render(request, "dashboard/asset_graph.html", ctx)
    resp["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp["Pragma"] = "no-cache"
    return resp


@require_GET
def audit_log(request):
    sid = _sid()
    ctx = _base_context()
    ctx.update(
        {
            "active": "audit",
            "audit": scope(AuditLog.objects.all(), sid)
            .select_related("actor")
            .order_by("-created_at")[:200],
        }
    )
    return render(request, "dashboard/audit_log.html", ctx)


@require_GET
def analysis(request):
    sid = _sid()
    ctx = _base_context()

    awaiting_qs = scope(AnalysisRun.objects.using(active_db()).all(), sid).filter(
        status=AnalysisRun.Status.AWAITING_CONTEXT
    )
    pending = None
    awaiting_id = request.GET.get("awaiting")
    if awaiting_id and awaiting_id.isdigit():
        pending = awaiting_qs.filter(pk=int(awaiting_id)).first()
    base_context = default_raw_system_context()
    if pending is not None:
        base_context = pending.raw_system_context or base_context

    ctx.update(
        {
            "active": "analysis",
            "scans": (
                scope(ScanJob.objects.using(active_db()).all(), sid)
                .filter(status=ScanJob.Status.COMPLETED)
                .order_by("-created_at")[:25]
            ),
            "runs": (
                scope(AnalysisRun.objects.using(active_db()).all(), sid)
                .annotate(assets_count=Count("assessments"))
                .order_by("-created_at")[:25]
            ),
            "pending": pending,
            "awaiting_count": awaiting_qs.count(),
            "default_context_json": json.dumps(base_context, indent=2),
        }
    )
    return render(request, "dashboard/analysis.html", ctx)


@require_GET
def analysis_detail(request, run_id):
    try:
        run, db = _load_run(run_id)
    except AnalysisRun.DoesNotExist:
        raise Http404(f"Analysis run {run_id} not found")
    sid = thread_session_id()
    if sid and run.session_id != sid:
        raise Http404(f"Analysis run {run_id} not found")
    assessments = list(
        AssetAssessment.objects.using(db)
        .filter(run=run)
        .select_related("asset")
        .order_by("id")
    )
    # Most urgent first: migration priority above overall risk.
    def _assessment_priority(a):
        m = (a.mosca_result or {}).get("mosca_assessment") or {}
        return (
            _priority_rank(m.get("migration_priority")),
            _priority_rank(m.get("overall_risk")),
            a.pk,
        )

    assessments.sort(key=_assessment_priority)

    summary = run.executive_summary or {}
    summary_rows = sorted(
        summary.get("rows", []),
        key=lambda r: (
            _priority_rank(r.get("migration_priority")),
            _priority_rank(r.get("overall_risk")),
            r.get("asset_id") or 0,
        ),
    )
    ctx = _base_context()
    plan = None
    if run.status == AnalysisRun.Status.COMPLETED:
        plan = MitigationPlan.objects.using(db).filter(run=run).first()
    ctx.update(
        {
            "active": "analysis",
            "run": run,
            "assessments": assessments,
            "summary_rows": summary_rows,
            "artifacts_url": reverse("analysis-artifacts", args=[run_id]),
            "mitigation_plan": plan,
        }
    )
    return render(request, "dashboard/analysis_detail.html", ctx)


@require_GET
def mitigation(request):
    """Mitigation overview: plans list + estate-level remediation stats."""
    sid = _sid()
    ctx = _base_context()

    plan_rows = []
    for p in (
        scope(MitigationPlan.objects.using(active_db()).all(), sid)
        .select_related("run__scan_job")
        .order_by("-created_at")[:50]
    ):
        summary = (p.document or {}).get("summary") or {}
        plan_rows.append(
            {
                "id": p.pk,
                "run_id": p.run_id,
                "target": p.run.scan_job.target,
                "status": p.status,
                "progress": p.progress,
                "generated_at": p.generated_at,
                "summary": summary,
            }
        )

    totals = {"assets": 0, "urgent": 0, "quantum_vulnerable": 0, "hndl_exposed": 0}
    for row in plan_rows:
        totals["assets"] += row["summary"].get("assets", 0)
        totals["urgent"] += row["summary"].get("urgent", 0)
        totals["quantum_vulnerable"] += row["summary"].get("quantum_vulnerable", 0)
        totals["hndl_exposed"] += row["summary"].get("hndl_exposed", 0)

    runs_unguarded = (
        scope(AnalysisRun.objects.using(active_db()).all(), sid)
        .filter(status=AnalysisRun.Status.COMPLETED, mitigation_plan__isnull=True)
        .annotate(assets_count=Count("assessments"))
        .order_by("-created_at")[:10]
    )

    ctx.update(
        {
            "active": "mitigation",
            "plans": plan_rows,
            "totals": totals,
            "runs_unguarded": runs_unguarded,
        }
    )
    return render(request, "dashboard/mitigation.html", ctx)


@require_GET
def mitigation_detail(request, plan_id):
    """One full mitigation plan: waves, blast radius, impact, suggestions."""
    sid = _sid()
    db = active_db()
    try:
        plan = (
            MitigationPlan.objects.using(db)
            .select_related("run__scan_job")
            .get(pk=plan_id)
        )
    except MitigationPlan.DoesNotExist:
        raise Http404(f"Mitigation plan {plan_id} not found")
    if sid and plan.session_id != sid:
        raise Http404(f"Mitigation plan {plan_id} not found")

    document = plan.document or {}
    summary = document.get("summary") or {}
    rows = document.get("rows") or []
    waves = document.get("waves") or []
    recommendations = document.get("recommendations") or []
    strategic = document.get("strategic_recommendations") or []
    blast = document.get("blast_radius") or {}
    twin = document.get("digital_twin") or {}
    quantum = document.get("quantum_risk") or {}
    qv_assets = list(quantum.get("post_quantum_vulnerable") or [])

    ctx = _base_context()
    ctx.update(
        {
            "active": "mitigation",
            "plan": plan,
            "document": document,
            "summary": summary,
            "rows": rows,
            "waves": waves,
            "recommendations": recommendations,
            "strategic": strategic,
            "blast": blast,
            "twin": twin,
            "quantum": quantum,
            "qv_assets": qv_assets,
            "api_base": "/api/mitigation/",
        }
    )
    return render(request, "dashboard/mitigation_detail.html", ctx)


@require_GET
def reports(request):
    """Reports page: on-demand full-pipeline report (PDF-as-base64) + exports."""
    from reports.report_builder import collect

    data = collect()
    kpis = data["kpis"]
    meta = data["meta"]
    ctx = _base_context()
    ctx.update(
        {
            "active": "reports",
            "page_title": "Reports",
            "page_desc": "Enterprise exports and the on-demand full-pipeline report.",
            "scope_label": meta["scope_label"],
            "counts": kpis,
            "mitigation_present": data["mitigation"] is not None,
            "api_full_json": reverse("report-full-json"),
            "api_full_html": reverse("report-full-html"),
            "api_full_pdf": reverse("report-full-pdf"),
            "exports": [
                {
                    "label": "Crypto asset inventory (CSV)",
                    "href": reverse("export-assets-csv"),
                },
                {
                    "label": "Crypto asset inventory (JSON)",
                    "href": reverse("export-assets-json"),
                },
                {
                    "label": "Raw findings (CSV)",
                    "href": reverse("export-raw-csv"),
                },
                {
                    "label": "Normalized findings (CSV)",
                    "href": reverse("export-normalized-csv"),
                },
            ],
        }
    )
    return render(request, "dashboard/reports.html", ctx)


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
    return scope(AssetAssessment.objects.using(active_db()).all(), _sid()).filter(run=latest).count()


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
    def stage(name, key, count, detail, done, href, sub=None):
        return {
            "name": name,
            "key": key,
            "count": count,
            "detail": detail,
            "done": done,
            "href": href,
            "sub": sub or [],
        }

    return [
        stage(
            "Scan / Discover",
            "discover",
            total,
            "intake repos, binaries, containers, certs, HSM, cloud",
            done=total > 0,
            href=reverse("dashboard-discovery"),
        ),
        stage(
            "Assess Quantum Risk",
            "assess",
            risk_counts["vulnerable"] + risk_counts["weak"] + risk_counts["moderate"],
            "Shor / Grover exposure · Mosca: data lifetime + migration vs horizon",
            done=total > 0 or analysis_done,
            href=reverse("dashboard-inventory"),
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
            href=reverse("dashboard-analysis"),
        ),
        stage(
            "PQC Mitigation",
            "mitigate",
            mitigation_assets or (1 if mitigation_done else 0),
            "hybrid + pure PQC (ML-KEM / ML-DSA) · auto-run per analysis",
            done=mitigation_done,
            href=reverse("dashboard-mitigation"),
        ),
        stage(
            "Full Report",
            "report",
            1 if mitigation_done else 0,
            "Enterprise PDF report · analysis + mitigation, generated on demand",
            done=mitigation_done and analysis_done,
            href=reverse("dashboard-reports"),
        ),
    ]
