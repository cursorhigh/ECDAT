"""Reports app — CSV/JSON export endpoints (current scope).

Exports of raw findings, normalized findings, and crypto asset inventory,
plus the on-demand enterprise full-pipeline report (HTML / PDF-as-base64).
"""

import base64
import csv
import json

from django.http import HttpResponse, JsonResponse
from django.views.decorators.clickjacking import xframe_options_sameorigin
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from core.models import log_action
from core.sessions import scope, thread_session_id
from segments.scraping.discovery.models import CryptoAsset, NormalizedFinding, RawFinding

from .pdf_renderer import render_pdf
from .report_builder import build_report


def _scoped(model):
    return scope(model.objects.all(), thread_session_id() or None)


def _csv_response(filename, header, rows):
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    writer = csv.writer(response)
    writer.writerow(header)
    writer.writerows(rows)
    return response


@require_GET
def export_assets_csv(request):
    rows = [
        (a.id, a.name, a.family, a.algorithm, a.key_size, a.curve, a.protocol,
         a.library, a.library_version, a.source_type, a.location, a.owner, a.inventory_status)
        for a in _scoped(CryptoAsset)
    ]
    log_action("export", "Exported crypto asset inventory (CSV)", "cryptoasset", "")
    return _csv_response(
        "ecdat_assets.csv",
        ["id", "name", "family", "algorithm", "key_size", "curve", "protocol",
         "library", "library_version", "source_type", "location", "owner", "inventory_status"],
        rows,
    )


@require_GET
def export_assets_json(request):
    data = list(_scoped(CryptoAsset).values())
    log_action("export", "Exported crypto asset inventory (JSON)", "cryptoasset", "")
    return JsonResponse({"assets": data})


@require_GET
def export_raw_csv(request):
    rows = [
        (f.id, f.source_type, f.location, f.status, f.ingested_at.isoformat() if f.ingested_at else "")
        for f in _scoped(RawFinding)
    ]
    log_action("export", "Exported raw findings (CSV)", "rawfinding", "")
    return _csv_response(
        "ecdat_raw_findings.csv",
        ["id", "source_type", "location", "status", "ingested_at"],
        rows,
    )


@require_GET
def export_normalized_csv(request):
    rows = [
        (n.id, n.family, n.algorithm, n.key_size, n.curve, n.protocol,
         n.library, n.library_version, n.confidence)
        for n in _scoped(NormalizedFinding)
    ]
    log_action("export", "Exported normalized findings (CSV)", "normalizedfinding", "")
    return _csv_response(
        "ecdat_normalized_findings.csv",
        ["id", "family", "algorithm", "key_size", "curve", "protocol",
         "library", "library_version", "confidence"],
        rows,
    )


def _build_snapshot():
    """Build the full-pipeline report document for the current scope."""
    from core.modes import active_db

    return build_report(sid=thread_session_id() or None, db=active_db())


@require_GET
@xframe_options_sameorigin
def full_report_html(request):
    """Return the full report as a self-contained HTML document.

    Same-origin framing allowed so the Reports page can preview it in an
    iframe without opening a new tab.
    """
    snapshot = _build_snapshot()
    log_action("report", "Generated full-pipeline report (HTML)", "report", "")
    response = HttpResponse(snapshot["html"], content_type="text/html; charset=utf-8")
    response["Content-Disposition"] = 'inline; filename="{0}"'.format(
        snapshot["filename"].replace(".pdf", ".html")
    )
    return response


@require_GET
def full_report_pdf(request):
    """Render the full report to PDF and stream it directly (save prompt)."""
    from core.modes import active_db

    snapshot = _build_snapshot()
    pdf = render_pdf(snapshot["html"])
    log_action("report", "Generated full-pipeline report (PDF)", "report", "")
    response = HttpResponse(pdf, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="{snapshot["filename"]}"'
    return response


@csrf_exempt
@require_POST
def full_report_json(request):
    """Render the full report and hand it to the front-end as base64.

    Payload: {"b64": "…", "filename": "….pdf", "mime": "application/pdf",
    "size": N, "generated_at": "…"} — the browser decodes the base64 into a
    Blob and offers the result for download. If PDF rendering is unavailable
    the HTML document is returned as base64 instead and the web layer falls
    back to an HTML save.
    """
    snapshot = _build_snapshot()
    try:
        payload = render_pdf(snapshot["html"])
        mime = "application/pdf"
        filename = snapshot["filename"]
        fmt = "pdf"
        render_error = None
    except RuntimeError as exc:
        payload = snapshot["html"].encode("utf-8")
        mime = "text/html; charset=utf-8"
        filename = snapshot["filename"].replace(".pdf", ".html")
        fmt = "html"
        render_error = str(exc)

    log_action(
        "report",
        f"Generated full-pipeline report ({fmt})",
        "report",
        "",
    )
    return JsonResponse(
        {
            "b64": base64.b64encode(payload).decode("ascii"),
            "filename": filename,
            "mime": mime,
            "format": fmt,
            "size": len(payload),
            "generated_at": snapshot["data"]["meta"]["generated_iso"],
            "render_error": render_error,
            "scope": snapshot["data"]["meta"]["scope_label"],
        }
    )
