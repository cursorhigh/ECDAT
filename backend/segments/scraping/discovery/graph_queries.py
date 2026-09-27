"""Graph queries.

The milestone's stated purpose is to answer three questions that no single
table could answer before:

* "What depends on this library?"
* "Which certificates does this application use?"
* "What breaks if I rotate this key?"

Each is a bounded traversal over ``GraphEdge`` that returns the paths taken, so
the answer is auditable rather than a bare count. All queries are session
scoped; a node belonging to another workspace is never traversed into.
"""

from __future__ import annotations

from .models import GraphEdge, GraphNode

# Traversal budget. An unbounded walk over a large estate is a denial of
# service against ourselves, and a partial answer is better than a hung request.
MAX_NODES = 400
MAX_DEPTH = 8


def _scoped(db: str, session_id):
    """Graph rows for one session, or none at all.

    This used to read "if a session is set, filter by it", which left every
    session's nodes and edges visible whenever none was selected. The graph tab
    then showed another scan's relationships as if they were this scan's.
    """
    from core.sessions import scope

    nodes = scope(GraphNode.objects.using(db), session_id)
    edges = scope(GraphEdge.objects.using(db), session_id)
    return nodes, edges


def _node_payload(node: GraphNode) -> dict:
    return {
        "id": node.id,
        "node_type": node.node_type,
        "node_type_display": node.get_node_type_display(),
        "key": node.key,
        "label": node.label or node.key,
        "family": node.family,
        "algorithm": node.algorithm,
        "asset_type": node.asset_type,
        "source_type": node.source_type,
        "location": node.location,
        "detail": node.detail or {},
    }


def find_node(db: str, session_id, node_type: str, key: str) -> GraphNode | None:
    nodes, _edges = _scoped(db, session_id)
    return nodes.filter(node_type=node_type, key=key).first()


def resolve(db: str, session_id, node_id: int) -> GraphNode | None:
    nodes, _edges = _scoped(db, session_id)
    return nodes.filter(pk=node_id).first()


def dependents(db: str, session_id, node_id: int, depth: int = 5) -> dict:
    """What depends on this node? Walks `depends_on` edges backwards.

    Backwards is the right direction: if A depends on B, then asking "what
    depends on B" must find A, and an outgoing walk from B would find nothing.
    """
    start = resolve(db, session_id, node_id)
    if start is None:
        return {"node": None, "paths": [], "truncated": False, "count": 0}

    _nodes, edges = _scoped(db, session_id)
    seen = {start.pk}
    paths: list[list[dict]] = []
    frontier = [start.pk]
    truncated = False

    for level in range(min(depth, MAX_DEPTH)):
        if not frontier or len(seen) >= MAX_NODES:
            truncated = bool(frontier) and len(seen) >= MAX_NODES
            break
        parents = list(
            edges.filter(
                to_node_id__in=frontier, relation_type=GraphEdge.RelationType.DEPENDS_ON
            )
            .exclude(from_node_id__in=seen)
            .select_related("from_node")[: MAX_NODES - len(seen)]
        )
        if not parents:
            break
        next_frontier = []
        for edge in parents:
            if edge.from_node_id in seen:
                continue
            seen.add(edge.from_node_id)
            next_frontier.append(edge.from_node_id)
            # Same shape as `reachable`: every query returns a list of
            # {"path": [...], "length": n} so a consumer never has to
            # special-case which question it asked.
            paths.append(
                {
                    "path": [
                        {"node": _node_payload(start), "relation": None, "why": {}},
                        {
                            "node": _node_payload(edge.from_node),
                            "relation": GraphEdge.RelationType.DEPENDS_ON,
                            "why": edge.evidence or {},
                        },
                    ],
                    "length": 1,
                }
            )
        frontier = next_frontier

    return {
        "node": _node_payload(start),
        "paths": paths,
        "truncated": truncated,
        "count": len(paths),
    }


def reachable(db: str, session_id, node_id: int, relations: tuple[str, ...],
              depth: int = 6) -> dict:
    """Everything reachable from a node over the given relation types."""
    start = resolve(db, session_id, node_id)
    if start is None:
        return {"node": None, "paths": [], "truncated": False, "count": 0}

    _nodes, edges = _scoped(db, session_id)
    seen = {start.pk}
    found: list[dict] = []
    # Seed with the same hop shape every later entry uses, so a consumer can
    # walk `entry["path"][i]["node"]` without special-casing the first element.
    frontier = [
        (start.pk, [{"node": _node_payload(start), "relation": None, "why": {}}])
    ]
    truncated = False

    for _level in range(min(depth, MAX_DEPTH)):
        if not frontier:
            break
        if len(seen) >= MAX_NODES:
            truncated = True
            break
        next_frontier = []
        for current_id, path in frontier:
            outgoing = edges.filter(
                from_node_id=current_id, relation_type__in=relations
            ).select_related("to_node")[: MAX_NODES - len(seen)]
            for edge in outgoing:
                if edge.to_node_id in seen:
                    continue
                seen.add(edge.to_node_id)
                extended = path + [
                    {
                        "node": _node_payload(edge.to_node),
                        "relation": edge.relation_type,
                        "why": edge.evidence or {},
                    }
                ]
                found.append({"path": extended, "length": len(extended) - 1})
                next_frontier.append((edge.to_node_id, extended))
        frontier = next_frontier

    return {
        "node": _node_payload(start),
        "paths": found,
        "truncated": truncated,
        "count": len(found),
    }


def certificates_of(db: str, session_id, node_id: int) -> dict:
    """Which certificates does this application (or file, or repo) use?"""
    return reachable(
        db, session_id, node_id,
        (
            GraphEdge.RelationType.CONTAINS,
            GraphEdge.RelationType.USES,
        ),
    )


def blast_radius_of(db: str, session_id, node_id: int) -> dict:
    """What breaks if this key, certificate or library goes away?

    Walks both directions, because breakage is caused by dependents *and* by
    whatever the artefact itself reaches. Grouped by node type so the answer is
    a summary first and a list second.
    """
    forward = reachable(
        db, session_id, node_id,
        (GraphEdge.RelationType.PROVIDES, GraphEdge.RelationType.USES),
        depth=4,
    )
    backward = dependents(db, session_id, node_id, depth=4)

    by_type: dict[str, int] = {}
    affected: list[dict] = []
    seen: set[int] = set()

    for entry in forward["paths"]:
        for hop in entry["path"][1:]:
            node = hop["node"]
            if node["id"] in seen:
                continue
            seen.add(node["id"])
            by_type[node["node_type"]] = by_type.get(node["node_type"], 0) + 1
            affected.append(node)
    for path in backward["paths"]:
        node = path["path"][-1]["node"]
        if node["id"] in seen:
            continue
        seen.add(node["id"])
        by_type[node["node_type"]] = by_type.get(node["node_type"], 0) + 1
        affected.append(node)

    return {
        "node": forward["node"] or backward["node"],
        "paths": forward["paths"] + backward["paths"],
        "affected": affected,
        "by_type": by_type,
        "count": len(affected),
        "truncated": forward["truncated"] or backward["truncated"],
    }


def graph_stats(db: str, session_id) -> dict:
    from django.db.models import Count

    nodes, edges = _scoped(db, session_id)
    by_type = nodes.values("node_type").annotate(count=Count("id"))
    by_relation = edges.values("relation_type").annotate(count=Count("id"))
    return {
        "nodes": nodes.count(),
        "edges": edges.count(),
        "nodes_by_type": {row["node_type"]: row["count"] for row in by_type},
        "edges_by_type": {row["relation_type"]: row["count"] for row in by_relation},
    }
