"""Reports app — CSV/JSON export endpoints (current scope).

Exports of raw findings, normalized findings, and crypto asset inventory.
"""

import csv
import json

from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_GET

from core.models import log_action
from discovery.models import CryptoAsset, NormalizedFinding, RawFinding


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
        for a in CryptoAsset.objects.all()
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
    data = list(CryptoAsset.objects.values())
    log_action("export", "Exported crypto asset inventory (JSON)", "cryptoasset", "")
    return JsonResponse({"assets": data})


@require_GET
def export_raw_csv(request):
    rows = [
        (f.id, f.source_type, f.location, f.status, f.ingested_at.isoformat() if f.ingested_at else "")
        for f in RawFinding.objects.all()
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
        for n in NormalizedFinding.objects.all()
    ]
    log_action("export", "Exported normalized findings (CSV)", "normalizedfinding", "")
    return _csv_response(
        "ecdat_normalized_findings.csv",
        ["id", "family", "algorithm", "key_size", "curve", "protocol",
         "library", "library_version", "confidence"],
        rows,
    )
