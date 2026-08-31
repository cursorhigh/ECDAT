"""Function views for the discovery app (action endpoints)."""

import json
import os

from django.db.models import Q
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .models import ScanJob
from .serializers import ScanJobSerializer


@csrf_exempt
def browse(request):
    """List local folders/drives for the path picker (GET).

    ?path=       -> list the subfolders of that folder (default: roots/drives)
    Returns any readable path on this machine. ECDAT runs locally, so this is
    a genuine path browser -- nothing is uploaded.
    """
    if request.method != "GET":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    path = (request.GET.get("path") or "").strip()

    if not path:
        # Return the available roots (drives on Windows, "/" on POSIX).
        return JsonResponse({"path": "", "parent": None, "folders": _list_roots()})

    path = os.path.abspath(os.path.expanduser(path))
    if not os.path.isdir(path):
        return JsonResponse({"detail": f"Not a directory: {path}"}, status=400)

    folders = []
    try:
        entries = sorted(os.scandir(path), key=lambda e: e.name.lower())
    except PermissionError:
        return JsonResponse({"path": path, "parent": None, "folders": [], "error": "Access denied"})

    for entry in entries:
        try:
            if entry.is_dir() and not entry.name.startswith("$"):
                folders.append(entry.name)
        except OSError:
            continue

    parent = os.path.dirname(path) if path != os.path.dirname(path) else None
    return JsonResponse({"path": path, "parent": parent or "", "folders": folders})


def _list_roots():
    if os.name == "nt":
        import string

        from ctypes import windll

        roots = []
        drives = []
        bitmask = windll.kernel32.GetLogicalDrives()
        for letter in string.ascii_uppercase:
            if bitmask & 1:
                drives.append(f"{letter}:\\")
            bitmask >>= 1
        for drive in drives:
            if os.path.isdir(drive):
                roots.append(drive)
        return roots
    return ["/"]


@csrf_exempt
def scan_preview(request):
    """Return the platform and the roots a given scan scope will walk (GET).

    ?scan_type=quick|whole|specified
    Lets the Discovery page explain what a Quick/Whole scan will actually
    cover on this machine before the user clicks Start.
    """
    from types import SimpleNamespace

    from .scanners.platform import detect_platform, resolve_scan_roots

    if request.method != "GET":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    scan_type = (request.GET.get("scan_type") or "quick").strip().lower()
    if scan_type not in ("quick", "whole", "specified"):
        return JsonResponse({"detail": f"Unknown scan type '{scan_type}'."}, status=400)

    job = SimpleNamespace(config={"scan_type": scan_type}, target=scan_type)
    roots = resolve_scan_roots(job)
    return JsonResponse(
        {
            "platform": detect_platform(),
            "scan_type": scan_type,
            "roots": [
                {"root": r.root, "label": r.label, "scan_all": r.scan_all} for r in roots
            ],
        }
    )


@csrf_exempt
def run_demo_scan(request):
    """Trigger the demo-mode scan (POST) and return the created ScanJob."""
    from .services import run_demo_scan as create_and_run

    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    job = create_and_run()
    return JsonResponse(ScanJobSerializer(job).data, status=201)


@csrf_exempt
def start_scan(request):
    """Start a scan with user-supplied parameters (POST).

    Body (JSON): {
        "scan_type": "quick" | "whole" | "specified",
        "source_type": "source_code",
        "target": "folder path (only for specified scan)",
        "options": { "<option>": true }
    }
    """
    from .services import ScanInspectionError, create_and_run_scan

    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    try:
        payload = json.loads(request.body or b"{}")
    except ValueError:
        return JsonResponse({"detail": "Invalid JSON body"}, status=400)

    source_type = payload.get("source_type", ScanJob.SourceType.SOURCE_CODE)
    target = payload.get("target", "")
    scan_type = payload.get("scan_type", "specified")
    options = payload.get("options") or {}

    from core.modes import active_db
    from core.sessions import create_scan_session

    using = active_db()
    label = os.path.basename(target.rstrip("\\/")) or scan_type or source_type
    ws = create_scan_session(request, label, using=using)

    try:
        job = create_and_run_scan(
            source_type=source_type,
            target=target,
            config=options,
            scan_type=scan_type,
            session_id=ws.pk,
        )
    except ScanInspectionError as exc:
        ws.delete()
        return JsonResponse({"detail": str(exc)}, status=400)

    data = ScanJobSerializer(job).data
    data["session"] = {"id": ws.pk, "name": ws.name}
    return JsonResponse(data, status=201)


@csrf_exempt
def graph_data(request):
    """Return everything the Asset Graph renders, across ALL discovery categories.

    GET -> {
        "assets":  [ {id, name, family, family_label, source_type, algorithm,
                       key_size, curve, protocol, library, location, owner} ... ],
        "findings": [ {id, family, family_label, source_type, algorithm, key_size,
                        curve, protocol, library, library_version, confidence,
                        location} ... ],
        "asset_relations": [ {from_asset, to_asset, relation_type} ... ],
        "finding_relations": [ {from, to, kind} ... ]   # family-correlations + finding->asset
    }
    Nodes are prefixed keys ('a'+asset_id / 'f'+finding_id) by the client.
    Output is bounded so the layout stays usable on huge scans.
    """
    from core.modes import active_db
    from core.sessions import scope, thread_session_id
    from .models import AssetRelation, CryptoAsset, NormalizedFinding

    if request.method != "GET":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    sid = thread_session_id()
    db = active_db()

    assets = scope(CryptoAsset.objects.all(), sid).order_by("name")
    asset_ids = set(assets.values_list("pk", flat=True))

    # Findings linked to the visible assets are the linkage backbone: they are
    # always included so an asset never renders as an island. Any remaining
    # node budget is filled with the other (unlinked) findings in family order.
    linked_finding_ids = set(
        CryptoAsset.objects.using(db).filter(pk__in=asset_ids).values_list(
            "normalized_findings__pk", flat=True
        )
    )
    qs = (
        scope(NormalizedFinding.objects.all(), sid)
        .select_related("raw_finding")
        .prefetch_related("assets")
    )
    linked_findings = list(
        qs.filter(pk__in=linked_finding_ids).order_by("family", "algorithm")[:400]
    )
    node_budget = 400 - len(linked_findings)
    others = []
    if node_budget > 0:
        others = list(
            qs.exclude(pk__in=linked_finding_ids).order_by("family", "algorithm")[:node_budget]
        )
    findings = linked_findings + others
    # Bound intra-family correlation edges (O(n^2) worst case).
    MAX_FAMILY_EDGES = 2500
    family_edges = []
    by_family: dict[str, list] = {}
    for f in findings:
        by_family.setdefault(f.family, []).append(f)
    for group in by_family.values():
        if len(group) < 2 or len(group) > 36:
            continue
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                family_edges.append(
                    {"from": f"f{group[i].pk}", "to": f"f{group[j].pk}", "kind": "family"}
                )
                if len(family_edges) >= MAX_FAMILY_EDGES:
                    break
            if len(family_edges) >= MAX_FAMILY_EDGES:
                break
        if len(family_edges) >= MAX_FAMILY_EDGES:
            break

    MAX_ASSIGN_EDGES = 3000
    assign_edges = []
    linked_by_asset: dict[int, list] = {}
    for f in findings:
        linked = [a for a in f.assets.all() if a.pk in asset_ids]
        if not linked:
            continue
        _fin = {
            "id": f.pk,
            "algorithm": f.algorithm or f.family,
            "family_label": f.get_family_display(),
        }
        for a in linked[:8]:
            linked_by_asset.setdefault(a.pk, []).append(_fin)
            assign_edges.append({"from": f"f{f.pk}", "to": f"a{a.pk}", "kind": "asset"})
            if len(assign_edges) >= MAX_ASSIGN_EDGES:
                break
        if len(assign_edges) >= MAX_ASSIGN_EDGES:
            break

    # Asset->asset edges. A work session sees its own relations plus any
    # global (legacy) relation, as long as both endpoints belong to a visible
    # asset — this is what keeps the graph linked under a session.
    rel_qs = AssetRelation.objects.using(db).all()
    if sid:
        rel_qs = rel_qs.filter(
            Q(session_id=sid)
            | Q(
                session__isnull=True,
                from_asset_id__in=asset_ids,
                to_asset_id__in=asset_ids,
            )
        )
    rels = list(rel_qs.values("from_asset", "to_asset", "relation_type")[:2000])

    return _no_cache(
        JsonResponse(
            {
                "assets": [
                {
                    "id": a.pk,
                    "name": a.name,
                    "family": a.family,
                    "family_label": a.get_family_display(),
                    "source_type": a.source_type,
                    "algorithm": a.algorithm,
                    "key_size": a.key_size,
                    "curve": a.curve,
                    "protocol": a.protocol,
                    "library": a.library,
                    "location": a.location,
                    "owner": a.owner,
                    "linked_findings": linked_by_asset.get(a.pk, [])[:12],
                }
                for a in assets
            ],
            "findings": [
                {
                    "id": f.pk,
                    "family": f.family,
                    "family_label": f.get_family_display(),
                    "source_type": f.raw_finding.source_type if f.raw_finding_id else None,
                    "algorithm": f.algorithm,
                    "key_size": f.key_size,
                    "curve": f.curve,
                    "protocol": f.protocol,
                    "library": f.library,
                    "library_version": f.library_version,
                    "confidence": round(f.confidence, 2),
                    "location": f.raw_finding.location,
                }
                for f in findings
            ],
            "asset_relations": list(rels),
            "finding_relations": family_edges + assign_edges,
        }
    )
)


def _no_cache(response):
    response["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response["Pragma"] = "no-cache"
    return response


@csrf_exempt
def graph_correlate(request):
    """(Re)build asset correlation edges for the current session (POST).

    POST /api/graph/correlate/  ->  {"created": N, "total": M}

    Lets a user fix a graph where correlation didn't happen (e.g. edges were
    created before correlation ran) without re-running the scan. Only the
    active session's assets are (re)correlated; returns how many edges were
    added and how many the graph can now render.
    """
    from core.modes import active_db
    from core.sessions import scope, thread_session_id

    from .correlation import build_correlations
    from .models import AssetRelation, CryptoAsset

    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    sid = thread_session_id()
    db = active_db()

    assets = CryptoAsset.objects.using(db).all()
    if sid:
        assets = assets.filter(session_id=sid)
    created = build_correlations(assets=assets, using=db)

    visible = set(a.pk for a in assets)
    rel_qs = AssetRelation.objects.using(db).all()
    if sid:
        rel_qs = rel_qs.filter(
            Q(session_id=sid)
            | Q(
                session__isnull=True,
                from_asset_id__in=visible,
                to_asset_id__in=visible,
            )
        )
    return _no_cache(JsonResponse({"created": created, "total": rel_qs.count()}))


@csrf_exempt
def scan_data(request):
    """Accept externally-supplied scan data (POST) and ingest it as findings.

    Lets an external scanner hand raw findings straight to ECDAT instead of
    having the app walk a local folder. Body (JSON):
        {
            "source_type": "source_code",
            "target": "optional label for the data source",
            "findings": [ { ...raw finding dict... }, ... ]
        }
    Each `findings` element follows the raw-finding schema used by the
    built-in scanners (see discovery/scanners/base.py). The normalizer,
    classifier and correlator then run exactly as for a folder scan.
    """
    from .services import ScanInspectionError, ingest_external_findings

    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    try:
        payload = json.loads(request.body or b"{}")
    except ValueError:
        return JsonResponse({"detail": "Invalid JSON body"}, status=400)

    findings = payload.get("findings")
    if not isinstance(findings, list):
        return JsonResponse({"detail": "`findings` must be a JSON array."}, status=400)

    from core.modes import active_db
    from core.sessions import create_scan_session

    ws = create_scan_session(
        request,
        (payload.get("target") or "").strip() or "external-data",
        using=active_db(),
    )

    try:
        job = ingest_external_findings(
            source_type=payload.get("source_type", ""),
            findings=findings,
            target=payload.get("target", ""),
            session_id=ws.pk,
        )
    except ScanInspectionError as exc:
        ws.delete()
        return JsonResponse({"detail": str(exc)}, status=400)

    data = ScanJobSerializer(job).data
    data["session"] = {"id": ws.pk, "name": ws.name}
    return JsonResponse(data, status=201)


