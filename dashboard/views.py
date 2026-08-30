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
    ctx = _base_context()
    ctx.update(
        {
            "active": "overview",
            "kpi": {
                "assets": CryptoAsset.objects.count(),
                "raw_findings": RawFinding.objects.count(),
                "normalized": NormalizedFinding.objects.count(),
                "scans": ScanJob.objects.count(),
                "relations": CryptoAsset.objects.aggregate(
                    total=Count("outgoing_relations")
                )["total"],
            },
            "pipeline": _pipeline_status(),
            "asset_by_family": _group(CryptoAsset.objects, "family"),
            "asset_by_source": _group(CryptoAsset.objects, "source_type"),
            "raw_by_source": _group(RawFinding.objects, "source_type"),
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
