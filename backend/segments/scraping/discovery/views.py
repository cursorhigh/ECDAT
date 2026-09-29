"""Function views for the discovery app (action endpoints)."""

import json
import os

from django.db.models import Q
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .models import ScanJob
from .serializers import ScanBatchSerializer, ScanJobSerializer


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
def scanners(request):
    """Describe the discovery scanners available in this deployment (GET).

    Returns one entry per recognised source type so the Discovery page can
    render sources, engines, and limit fields from the registry instead of
    hard-coding them. Entries are either `available` (backed by an
    implementation) or `planned` (recognised, not yet implemented).
    """
    from django.conf import settings

    if request.method != "GET":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    from .scanners import list_scanners
    from .scanners.platform import detect_platform, get_scan_limits, resolve_scan_roots

    entries = list_scanners()

    # What each scope will actually read. The UI must not describe a scan in
    # terms the platform does not implement, so the real locations come from
    # the same resolver the scanners use.
    class _Probe:
        """Minimal stand-in so the resolver can be asked "what would you read?"."""

        def __init__(self, scan_type):
            self.config = {"scan_type": scan_type}
            self.target = scan_type

    scopes = {}
    for scan_type in ("quick", "whole"):
        try:
            roots = resolve_scan_roots(_Probe(scan_type))
        except Exception:  # noqa: BLE001 - never fail the registry response
            roots = []
        scopes[scan_type] = {
            "roots": [{"root": r.root, "label": r.label} for r in roots],
            "unbounded": all(
                getattr(limit, name) is None
                for name in ("max_files", "max_depth", "max_file_size")
                for limit in [get_scan_limits(_Probe(scan_type))]
            ),
        }

    return JsonResponse(
        {
            "scanners": entries,
            "available": [e["id"] for e in entries if e["status"] == "available"],
            "platform": detect_platform(),
            "scopes": scopes,
        }
    )


@csrf_exempt
def start_scan(request):
    """Start a scan with user-supplied parameters (POST).

    Body (JSON): {
        "scan_type": "quick" | "whole" | "specified",
        "source_type": "source_code",
        "target": "folder path (only for specified scan)",
        "options": { "<option>": true }
    }

    The job is created queued and dispatched through the configured executor
    (daemon thread by default, huey under ECDAT_QUEUE_ASYNC=1), so the request
    returns immediately and the scan can be cancelled via
    POST /api/scans/<id>/cancel/.
    """
    from .services import ScanInspectionError, create_and_run_scan, create_batch_scan

    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    try:
        payload = json.loads(request.body or b"{}")
    except ValueError:
        return JsonResponse({"detail": "Invalid JSON body"}, status=400)

    source_type = payload.get("source_type", ScanJob.SourceType.SOURCE_CODE)
    # A caller may ask for several sources in one action. `source_types` wins
    # when present so a client never has to guess which key is authoritative.
    source_types = payload.get("source_types")
    target = payload.get("target", "")
    scan_type = payload.get("scan_type", "specified")
    options = payload.get("options") or {}

    if source_types is not None and not isinstance(source_types, list):
        return JsonResponse({"detail": "`source_types` must be a list."}, status=400)
    requested = [s for s in (source_types or []) if s]
    if not requested:
        requested = [source_type]

    from core.modes import active_db
    from core.sessions import create_scan_session

    using = active_db()
    label = os.path.basename(target.rstrip("\\/")) or scan_type or requested[0]
    ws = create_scan_session(request, label, using=using)

    if len(requested) == 1:
        try:
            job = create_and_run_scan(
                source_type=requested[0],
                target=target,
                config=options,
                scan_type=scan_type,
                session_id=ws.pk,
            )
        except ScanInspectionError as exc:
            ws.delete()
            return JsonResponse({"detail": str(exc)}, status=400)
        single = ScanJobSerializer(job).data
        single["session"] = {"id": ws.pk, "name": ws.name}
        return JsonResponse(single, status=201)

    try:
        batch = create_batch_scan(
            source_types=requested,
            target=target,
            scan_type=scan_type,
            session_id=ws.pk,
        )
    except ScanInspectionError as exc:
        ws.delete()
        return JsonResponse({"detail": str(exc)}, status=400)

    data = ScanBatchSerializer(batch).data
    data["session"] = {"id": ws.pk, "name": ws.name}
    return JsonResponse(data, status=201)


@csrf_exempt
def scan_batch(request, batch_id):
    """Read a multi-source run (GET /api/scan-batches/<id>/).

    Status and progress are recomputed from the child jobs on every read, so
    the summary can never drift from what the individual sources achieved.
    """
    if request.method != "GET":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    from core.modes import active_db
    from core.sessions import thread_session_id
    from .models import ScanBatch
    from .services import refresh_batch_status

    db = active_db()
    sid = thread_session_id()
    batch = ScanBatch.objects.using(db).filter(pk=batch_id, session_id=sid).first()
    if batch is None:
        return JsonResponse({"detail": f"Scan batch {batch_id} not found."}, status=404)
    refresh_batch_status(batch, db)
    batch.refresh_from_db(using=db)
    return JsonResponse(ScanBatchSerializer(batch).data)


@csrf_exempt
def cancel_scan_batch(request, batch_id):
    """Cancel every source in a multi-source run (POST /api/scan-batches/<id>/cancel/)."""
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    from core.modes import active_db
    from core.sessions import thread_session_id
    from .models import ScanBatch
    from .services import cancel_batch

    db = active_db()
    sid = thread_session_id()
    batch = ScanBatch.objects.using(db).filter(pk=batch_id, session_id=sid).first()
    if batch is None:
        return JsonResponse({"detail": f"Scan batch {batch_id} not found."}, status=404)
    affected = cancel_batch(batch, db)
    return JsonResponse({"id": batch.pk, "status": batch.status, "cancelled": affected})


@csrf_exempt
def handoff(request):
    """The Discover -> Understand dataset (GET /api/handoff/).

    Optional filters: `scan_id` for a single scan, `limit`.

    This is the hand-off contract made inspectable: the six questions Understand
    must be able to answer, whether each finding can answer them, and the scan
    coverage behind the dataset.
    """
    from core.modes import active_db
    from core.sessions import thread_session_id
    from .handoff import CONTRACT_QUESTIONS, build_handoff
    from .models import ScanJob

    if request.method != "GET":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    db = active_db()
    sid = thread_session_id()

    scan_job = None
    raw_scan_id = request.GET.get("scan_id")
    if raw_scan_id:
        try:
            scan_id = int(raw_scan_id)
        except (TypeError, ValueError):
            return JsonResponse({"detail": "scan_id must be an integer."}, status=400)
        scan_job = ScanJob.objects.using(db).filter(pk=scan_id, session_id=sid).first()
        if scan_job is None:
            return JsonResponse(
                {"detail": f"Scan {scan_id} not found."}, status=404
            )

    try:
        limit = max(1, min(int(request.GET.get("limit", 500)), 5000))
    except (TypeError, ValueError):
        return JsonResponse({"detail": "limit must be an integer."}, status=400)

    # `summary=1` answers "is this dataset fit to reason over?" without shipping
    # it. The contract is still evaluated across every finding, because a verdict
    # computed from a truncated page would describe the page, not the scan.
    summary_only = request.GET.get("summary") == "1"
    if summary_only:
        limit = 5000

    handoff = build_handoff(db, session_id=sid, scan_job=scan_job, limit=limit)
    payload = handoff.as_dict()
    payload["questions"] = [
        {
            "key": question,
            "label": _HANDOFF_QUESTION_LABELS.get(question, question),
            "unanswered": payload["contract"]["unanswered_by_question"].get(question, 0),
        }
        for question in CONTRACT_QUESTIONS
    ]
    # Truncation is reported by the handoff itself, which had to fetch an extra
    # row to know it; re-deriving it here compared a limit against a list that
    # was already cut to size and could never be true.
    if summary_only:
        payload.pop("findings", None)
    return JsonResponse(payload)

_HANDOFF_QUESTION_LABELS = {
    "what_was_discovered": "What was discovered?",
    "where_was_it_discovered": "Where was it discovered?",
    "how_was_it_discovered": "How was it discovered?",
    "how_confident_are_we": "How confident are we?",
    "what_asset_does_it_belong_to": "What asset does it belong to?",
    "what_does_it_depend_on": "What does it depend on?",
}


@csrf_exempt
def graph_index(request):
    """Read the unified relationship graph (GET /api/graph-index/).

    Optional filters: `node_type`, `relation_type`, `limit`. `rebuild=1`
    recomputes the index from the authoritative tables, which is safe to repeat.
    """
    from core.api import require_scan_scope
    from core.modes import active_db
    from core.sessions import scope, thread_session_id
    from .graph_index import build_graph_index
    from .graph_queries import _node_payload, graph_stats
    from .models import GraphEdge, GraphNode

    if request.method != "GET":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    db = active_db()
    sid = thread_session_id()

    if request.GET.get("rebuild") == "1":
        # Rebuilding with no session would index the entire estate into
        # session-less graph rows, which then no single scan could see and
        # every session would be polluted by.
        require_scan_scope(sid)
        result = build_graph_index(db, session_id=sid)
        return JsonResponse(
            {
                "rebuilt": True,
                "nodes_created": result.nodes_created,
                "nodes_reused": result.nodes_reused,
                "edges_created": result.edges_created,
                "skipped_no_path": result.skipped_no_path,
                # Surfaced rather than swallowed: a new asset type with no node
                # mapping is invisible everywhere else.
                "unmapped_asset_types": sorted(result.unmapped_asset_types),
            }
        )

    # `scope` returns nothing when there is no active session. Filtering by hand
    # with "if a session is set" left the whole estate's graph on screen, so one
    # scan's tab could show another scan's relationships.
    nodes = scope(GraphNode.objects.using(db), sid)
    edges = scope(GraphEdge.objects.using(db), sid)

    node_type = request.GET.get("node_type")
    relation_type = request.GET.get("relation_type")
    if node_type:
        nodes = nodes.filter(node_type=node_type)
    if relation_type:
        edges = edges.filter(relation_type=relation_type)

    try:
        limit = max(1, min(1000, int(request.GET.get("limit", 200))))
    except ValueError:
        limit = 200

    return JsonResponse(
        {
            "stats": graph_stats(db, sid),
            "nodes": [_node_payload(n) for n in nodes[:limit]],
            "edges": [
                {
                    "from": e.from_node_id,
                    "to": e.to_node_id,
                    "kind": e.relation_type,
                    "why": e.evidence or {},
                }
                for e in edges.select_related("from_node", "to_node")[:limit]
            ],
        }
    )


@csrf_exempt
def graph_impact(request, node_id):
    """Answer an impact question about one graph node (GET /api/graph-index/<id>/impact/).

    `question` is one of:
      dependents         - what depends on this?
      certificates      - which certificates does this use?
      blast-radius      - what breaks if this goes away?
    """
    from core.api import require_scan_scope
    from core.modes import active_db
    from core.sessions import thread_session_id
    from .graph_queries import blast_radius_of, certificates_of, dependents

    if request.method != "GET":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    db = active_db()
    sid = thread_session_id()
    question = (request.GET.get("question") or "blast-radius").strip().lower()

    if question not in ("dependents", "certificates", "certs", "blast-radius", "blast"):
        return JsonResponse(
            {"detail": f"Unknown question '{question}'."}, status=400
        )

    # Asking about one specific node needs a scan to ask it in. Returning an
    # empty path list instead would read as "this node has no impact", which is
    # a different and much more dangerous statement.
    require_scan_scope(sid)

    if question == "dependents":
        payload = dependents(db, sid, node_id)
    elif question in ("certificates", "certs"):
        payload = certificates_of(db, sid, node_id)
    else:  # "blast-radius" / "blast", validated above
        payload = blast_radius_of(db, sid, node_id)

    payload["question"] = question
    return JsonResponse(payload)


@csrf_exempt
def cancel_scan(request, scan_id):
    """Cancel a scan job (POST /api/scans/<id>/cancel/).

    Only queued/running scans are cancellable. A cancel on a running scan moves
    it to "cancelling"; the worker confirms "cancelled" once it has stopped, so
    the reported status always reflects work that actually halted.
    """
    from core.modes import active_db
    from core.sessions import thread_session_id
    from .services import cancel_scan_job

    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    db = active_db()
    # Every read viewset scopes by session, so cancellation must too: otherwise
    # a guessable id lets one workspace stop another workspace's running scan.
    sid = thread_session_id()
    try:
        job = ScanJob.objects.using(db).get(pk=scan_id, session_id=sid)
    except ScanJob.DoesNotExist:
        return JsonResponse({"detail": f"Scan job {scan_id} not found."}, status=404)

    if not cancel_scan_job(job):
        return JsonResponse(
            {"detail": f"Scan {scan_id} is not cancellable (status: {job.status})."},
            status=400,
        )
    return JsonResponse(
        {
            "id": job.pk,
            "status": job.status,
            "status_display": job.get_status_display(),
        }
    )


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
    # asset — this is what keeps the graph linked under a session. With no
    # active session there are no visible assets, so there are no relations to
    # report either.
    rel_qs = AssetRelation.objects.using(db)
    if sid:
        rel_qs = rel_qs.filter(
            Q(session_id=sid)
            | Q(
                session__isnull=True,
                from_asset_id__in=asset_ids,
                to_asset_id__in=asset_ids,
            )
        )
    else:
        rel_qs = rel_qs.none()
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
            # Additive: the dependency graph is a separate node/edge set, so
            # existing consumers of the four keys above are unaffected.
            "dependency_nodes": _dependency_nodes(sid),
            "dependency_edges": _dependency_edges(sid),
        }
    )
)


def _dependency_nodes(session_id) -> list[dict]:
    """Dependency graph nodes for the active workspace."""
    from core.sessions import scope

    from .models import Dependency

    if not session_id:
        return []
    rows = scope(Dependency.objects.all(), session_id).order_by("-is_crypto", "package")[:600]
    return [
        {
            "id": f"d{row.pk}",
            "package": row.package,
            "version": row.version,
            "ecosystem": row.ecosystem,
            "scope": row.scope,
            "is_crypto": row.is_crypto,
            "relevance": row.relevance,
            "capability": row.capability,
            "key_service": row.key_service,
        }
        for row in rows
    ]


def _dependency_edges(session_id) -> list[dict]:
    """Dependency graph edges: transitive requires plus library->asset links."""
    from core.sessions import scope

    from .models import DependencyRelation

    if not session_id:
        return []
    edges = scope(DependencyRelation.objects.all(), session_id).select_related(
        "from_dependency", "to_dependency", "to_asset"
    )[:1500]

    out: list[dict] = []
    for edge in edges:
        if edge.to_dependency_id:
            out.append(
                {
                    "from": f"d{edge.from_dependency_id}",
                    "to": f"d{edge.to_dependency_id}",
                    "kind": edge.relation_type,
                    "detail": edge.detail,
                }
            )
        elif edge.to_asset_id:
            out.append(
                {
                    "from": f"d{edge.from_dependency_id}",
                    "to": f"a{edge.to_asset_id}",
                    "kind": edge.relation_type,
                    "detail": edge.detail,
                }
            )
    return out


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
    from core.api import require_scan_scope
    from core.modes import active_db
    from core.sessions import scope, thread_session_id

    from .correlation import build_correlations
    from .models import AssetRelation, CryptoAsset

    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    sid = thread_session_id()
    db = active_db()

    # Correlating rewrites relation rows, so it is refused outright without a
    # scan rather than silently operating on the whole database.
    require_scan_scope(sid)

    # `scope` yields nothing without a session, so this stays a no-op even if the
    # guard is ever bypassed.
    assets = scope(CryptoAsset.objects.using(db).all(), sid)
    created = build_correlations(assets=assets, using=db)

    visible = set(a.pk for a in assets)
    rel_qs = AssetRelation.objects.using(db)
    if sid:
        rel_qs = rel_qs.filter(
            Q(session_id=sid)
            | Q(
                session__isnull=True,
                from_asset_id__in=visible,
                to_asset_id__in=visible,
            )
        )
    else:
        rel_qs = rel_qs.none()
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
    Each `findings` element is validated against the shared handoff contract
    (schema/contracts/raw_finding.py) before anything is written, so a
    malformed export is rejected with a fixable message instead of failing
    part-way through. The normalizer, classifier and correlator then run
    exactly as for a folder scan.
    """
    from .services import (
        ScanInspectionError,
        ingest_external_findings,
        validate_import_payload,
    )

    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    try:
        payload = json.loads(request.body or b"{}")
    except ValueError:
        return JsonResponse({"detail": "Invalid JSON body"}, status=400)

    # Validate before a session or job row exists, so a bad payload leaves no
    # empty workspace behind.
    try:
        source_type, target, findings = validate_import_payload(payload)
    except ScanInspectionError as exc:
        return JsonResponse({"detail": str(exc)}, status=400)

    from core.modes import active_db
    from core.sessions import create_scan_session

    ws = create_scan_session(request, target or "external-data", using=active_db())

    try:
        job = ingest_external_findings(
            source_type=source_type,
            findings=findings,
            target=target,
            session_id=ws.pk,
        )
    except ScanInspectionError as exc:
        ws.delete()
        return JsonResponse({"detail": str(exc)}, status=400)

    data = ScanJobSerializer(job).data
    data["session"] = {"id": ws.pk, "name": ws.name}
    return JsonResponse(data, status=201)


