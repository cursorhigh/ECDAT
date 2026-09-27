"""Builds the unified relationship graph.

Milestone 10 of the discovery roadmap: one navigable graph across every kind
of entity, replacing the two disconnected ones (asset-to-asset relations and
dependency relations) that could not be joined.

Design rules this module follows:

* **Nothing is invented.** An edge is emitted only when a recorded fact supports
  it: a stored relation, an observation at a path, or a declared manifest. Every
  edge carries ``evidence`` naming that fact, so the UI can always answer "why
  is this connected?".
* **The index is derived.** CryptoAsset, Dependency and ScanJob remain
  authoritative. GraphNode/GraphEdge can be deleted and rebuilt at any time.
* **Rebuilding is idempotent.** Node keys are stable and edges are unique on
  (from, to, relation), so a rescan converges instead of accumulating.
* **No cross-session leakage.** Every query is scoped, and a node belonging to
  another workspace is never linked.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from core.sessions import scope

from .models import (
    AssetOccurrence,
    AssetRelation,
    CryptoAsset,
    Dependency,
    DependencyRelation,
    GraphEdge,
    GraphNode,
    NormalizedFinding,
    RawFinding,
    ScanJob,
)

# Which graph node type each discovered asset type becomes. Anything unmapped is
# reported rather than silently bucketed, so a new asset type is visible here.
# Built from the taxonomy at import time so a new AssetType cannot break the
# builder the way a hard-coded name would.
_ASSET_NODE_TYPE = {
    CryptoAsset.AssetType.CERTIFICATE: GraphNode.NodeType.CERTIFICATE,
    CryptoAsset.AssetType.KEY_REFERENCE: GraphNode.NodeType.KEY,
    CryptoAsset.AssetType.LIBRARY: GraphNode.NodeType.LIBRARY,
    CryptoAsset.AssetType.DEPENDENCY: GraphNode.NodeType.DEPENDENCY,
    CryptoAsset.AssetType.NETWORK_ENDPOINT: GraphNode.NodeType.ENDPOINT,
    CryptoAsset.AssetType.API: GraphNode.NodeType.API,
    CryptoAsset.AssetType.HARDWARE: GraphNode.NodeType.INFRASTRUCTURE,
    CryptoAsset.AssetType.INFRASTRUCTURE: GraphNode.NodeType.INFRASTRUCTURE,
    CryptoAsset.AssetType.CLOUD_RESOURCE: GraphNode.NodeType.INFRASTRUCTURE,
    CryptoAsset.AssetType.CONTAINER: GraphNode.NodeType.CONTAINER,
    CryptoAsset.AssetType.FIRMWARE: GraphNode.NodeType.CONTAINER,
    CryptoAsset.AssetType.APPLICATION: GraphNode.NodeType.APPLICATION,
    CryptoAsset.AssetType.REPOSITORY: GraphNode.NodeType.REPOSITORY,
}

# How a file uses an artefact it was observed in.
_FILE_TO_ASSET = {
    GraphNode.NodeType.CERTIFICATE: GraphEdge.RelationType.CONTAINS,
    GraphNode.NodeType.KEY: GraphEdge.RelationType.CONTAINS,
    GraphNode.NodeType.CONTAINER: GraphEdge.RelationType.CONTAINS,
    GraphNode.NodeType.LIBRARY: GraphEdge.RelationType.USES,
    GraphNode.NodeType.DEPENDENCY: GraphEdge.RelationType.USES,
    GraphNode.NodeType.ALGORITHM: GraphEdge.RelationType.USES,
    GraphNode.NodeType.API: GraphEdge.RelationType.USES,
    GraphNode.NodeType.ENDPOINT: GraphEdge.RelationType.USES,
    GraphNode.NodeType.INFRASTRUCTURE: GraphEdge.RelationType.USES,
}


@dataclass
class BuildResult:
    nodes_created: int = 0
    nodes_reused: int = 0
    edges_created: int = 0
    unmapped_asset_types: set[str] = field(default_factory=set)
    skipped_no_path: int = 0


def _node_key(node_type: str, identity: str) -> str:
    return f"{node_type}:{identity[:480]}"


def _upsert_node(db: str, session_id, node_type: str, key: str, **fields) -> GraphNode:
    node, created = GraphNode.objects.using(db).update_or_create(
        session_id=session_id,
        node_type=node_type,
        key=key[:512],
        defaults=fields,
    )
    return node, created


def _upsert_edge(db: str, session_id, source: GraphNode, target: GraphNode,
                 relation: str, evidence: dict) -> bool:
    if source.pk == target.pk:
        return False
    _row, created = GraphEdge.objects.using(db).get_or_create(
        from_node=source,
        to_node=target,
        relation_type=relation,
        defaults={"session_id": session_id, "evidence": evidence, "confidence": 1.0},
    )
    return created


def _file_identity(path: str) -> str:
    return path.replace("\\", "/")


def _relative_to(path: str, root: str) -> str | None:
    try:
        return os.path.relpath(path, root).replace("\\", "/")
    except ValueError:
        return None


def build_graph_index(db: str, session_id=None, scan_job: ScanJob | None = None) -> BuildResult:
    """(Re)build the graph index for a session, or for one scan.

    Passing ``scan_job`` narrows the build to that scan's findings while still
    using the session's full node set, so a follow-up scan enriches the existing
    graph instead of building a disconnected one.
    """
    result = BuildResult()

    # --- repositories: one per distinct scan target ------------------------
    jobs = ScanJob.objects.using(db)
    if session_id is not None:
        jobs = jobs.filter(session_id=session_id)
    if scan_job is not None:
        jobs = jobs.filter(pk=scan_job.pk)

    roots: dict[str, str] = {}
    for job in jobs:
        target = (job.target or "").strip()
        if not target or target.lower() in ("quick", "whole"):
            continue
        key = _node_key(GraphNode.NodeType.REPOSITORY, _file_identity(target))
        node, created = _upsert_node(
            db,
            session_id,
            GraphNode.NodeType.REPOSITORY,
            key,
            label=os.path.basename(target.rstrip("\\/")) or target,
            ref_model="ScanJob",
            ref_id=job.pk,
            source_type=job.source_type,
            location=target,
            detail={"target": target, "last_scan": job.pk},
        )
        result.nodes_created += int(created)
        result.nodes_reused += int(not created)
        roots[target] = node.key

    # --- files: one per distinct observed path -----------------------------
    findings = NormalizedFinding.objects.using(db).select_related(
        "raw_finding", "raw_finding__scan_job"
    )
    if session_id is not None:
        findings = findings.filter(raw_finding__session_id=session_id)
    if scan_job is not None:
        findings = findings.filter(raw_finding__scan_job=scan_job)

    file_nodes: dict[str, GraphNode] = {}
    library_mentions: list[tuple[str, str]] = []
    finding_rows = list(
        findings.values(
            "id",
            "algorithm",
            "family",
            "kind",
            "key_size",
            "curve",
            "library",
            "protocol",
            "raw_finding__location",
            "raw_finding__source_path",
            "raw_finding__source_type",
        )
    )

    for row in finding_rows:
        path = row["raw_finding__source_path"] or row["raw_finding__location"] or ""
        if not path:
            result.skipped_no_path += 1
            continue
        identity = _file_identity(path)
        if row["library"]:
            library_mentions.append((identity, row["library"].strip()))
        if identity in file_nodes:
            continue
        key = _node_key(GraphNode.NodeType.FILE, identity)
        node, created = _upsert_node(
            db,
            session_id,
            GraphNode.NodeType.FILE,
            key,
            label=os.path.basename(path) or identity,
            ref_model="RawFinding",
            source_type=row["raw_finding__source_type"] or "",
            location=path,
            detail={"path": path},
        )
        result.nodes_created += int(created)
        result.nodes_reused += int(not created)
        file_nodes[identity] = node

        # Record which repository and application this file sits under. The
        # root is whichever declared target actually contains the path.
        for target in roots:
            relative = _relative_to(path, target)
            if relative is None or relative.startswith(".."):
                continue
            repo_node = GraphNode.objects.using(db).filter(
                session_id=session_id,
                node_type=GraphNode.NodeType.REPOSITORY,
                key=_node_key(GraphNode.NodeType.REPOSITORY, _file_identity(target)),
            ).first()
            if repo_node is None:
                continue
            if _upsert_edge(
                db, session_id, repo_node, node, GraphEdge.RelationType.CONTAINS,
                {"why": "path is inside the scanned target", "target": target},
            ):
                result.edges_created += 1
            # First path segment below the target is treated as the application
            # boundary; deeper files belong to it. Recorded as a fact about the
            # path, not a guess about the code.
            parts = relative.split("/")
            if len(parts) > 1:
                app_key = _node_key(
                    GraphNode.NodeType.APPLICATION, f"{_file_identity(target)}#{parts[0]}"
                )
                app_node, app_created = _upsert_node(
                    db,
                    session_id,
                    GraphNode.NodeType.APPLICATION,
                    app_key,
                    label=parts[0],
                    location=os.path.join(target, parts[0]),
                    detail={"root": target},
                )
                result.nodes_created += int(app_created)
                result.nodes_reused += int(not app_created)
                _upsert_edge(
                    db, session_id, repo_node, app_node,
                    GraphEdge.RelationType.CONTAINS,
                    {"why": "application directory under the scanned target"},
                )
                if _upsert_edge(
                    db, session_id, app_node, node,
                    GraphEdge.RelationType.CONTAINS,
                    {"why": "file path under the application directory", "path": path},
                ):
                    result.edges_created += 1
            break

    # --- algorithms: the thing everything else revolves around ------------
    # Taken from NormalizedFinding, which is the authoritative record of what
    # was observed. Without this the graph has files and libraries but no
    # statement about which cryptography is actually in use, and no algorithm
    # or key node would ever exist.
    algorithm_rows = findings.values(
        "algorithm", "family", "key_size", "curve", "library",
    )
    algorithm_nodes: dict[tuple, GraphNode] = {}
    for row in algorithm_rows.iterator():
        family = row["family"] or "unknown"
        algorithm = row["algorithm"] or ""
        if not algorithm and family == "unknown":
            # Nothing was actually identified; an "unknown" node with no
            # identity would collapse every unclassified finding into one.
            continue
        identity = "|".join(
            [family, algorithm, str(row["key_size"] or ""), row["curve"] or ""]
        )
        node_type = (
            GraphNode.NodeType.CERTIFICATE
            if family == "certificate"
            else GraphNode.NodeType.KEY
            if family in ("rsa", "dsa", "ecc", "pqc")
            else GraphNode.NodeType.ALGORITHM
        )
        key = _node_key(node_type, identity)
        if key in algorithm_nodes:
            continue
        node, created = _upsert_node(
            db,
            session_id,
            node_type,
            key,
            label=algorithm or family,
            family=family,
            algorithm=algorithm,
            detail={"key_size": row["key_size"], "curve": row["curve"] or ""},
        )
        result.nodes_created += int(created)
        result.nodes_reused += int(not created)
        algorithm_nodes[key] = node

    # --- file -> algorithm: the core discovery statement -------------------
    for row in finding_rows:
        path = row["raw_finding__source_path"] or row["raw_finding__location"] or ""
        file_node = file_nodes.get(_file_identity(path)) if path else None
        if file_node is None:
            continue
        identity = "|".join(
            [row["family"] or "unknown", row["algorithm"] or "",
             str(row["key_size"] or ""), row["curve"] or ""]
        )
        for node_type in (GraphNode.NodeType.CERTIFICATE, GraphNode.NodeType.KEY,
                          GraphNode.NodeType.ALGORITHM):
            node = algorithm_nodes.get(_node_key(node_type, identity))
            if node is None:
                continue
            if _upsert_edge(
                db, session_id, file_node, node, GraphEdge.RelationType.USES,
                {"why": "observed in this file", "path": path,
                 "finding": row["id"]},
            ):
                result.edges_created += 1
            break

    # --- assets: one node per discovered artefact --------------------------
    assets = CryptoAsset.objects.using(db)
    if session_id is not None:
        assets = assets.filter(session_id=session_id)
    if scan_job is not None:
        # An asset has no direct scan_job; it is tied to a scan through the
        # findings it was observed in.
        assets = assets.filter(
            occurrences__scan_job=scan_job.pk,
        ).distinct()

    asset_nodes: dict[int, GraphNode] = {}
    for asset in assets.iterator():
        node_type = _ASSET_NODE_TYPE.get(asset.asset_type)
        if node_type is None:
            result.unmapped_asset_types.add(asset.asset_type)
            continue
        key = _node_key(node_type, asset.identifier or str(asset.pk))
        node, created = _upsert_node(
            db,
            session_id,
            node_type,
            key,
            label=asset.name or asset.algorithm or asset.family,
            ref_model="CryptoAsset",
            ref_id=asset.pk,
            family=asset.family or "",
            algorithm=asset.algorithm or "",
            asset_type=asset.asset_type or "",
            source_type=asset.source_type or "",
            location=asset.location or "",
            detail={"key_size": asset.key_size, "protocol": asset.protocol,
                    "library": asset.library, "owner": asset.owner},
        )
        result.nodes_created += int(created)
        result.nodes_reused += int(not created)
        asset_nodes[asset.pk] = node

    # --- dependencies: one node per package -------------------------------
    dependencies = Dependency.objects.using(db)
    if session_id is not None:
        dependencies = dependencies.filter(session_id=session_id)
    if scan_job is not None:
        dependencies = dependencies.filter(scan_job=scan_job)

    dependency_nodes: dict[int, GraphNode] = {}
    for dependency in dependencies.iterator():
        identity = f"{dependency.ecosystem or 'unknown'}:{dependency.package}"
        key = _node_key(GraphNode.NodeType.DEPENDENCY, identity)
        node, created = _upsert_node(
            db,
            session_id,
            GraphNode.NodeType.DEPENDENCY,
            key,
            label=dependency.package,
            ref_model="Dependency",
            ref_id=dependency.pk,
            family=dependency.family or "",
            asset_type=dependency.relevance or "",
            location=dependency.location or "",
            detail={
                "version": dependency.version,
                "ecosystem": dependency.ecosystem,
                "scope": dependency.scope,
                "is_crypto": dependency.is_crypto,
                "capability": dependency.capability,
                "key_service": dependency.key_service,
            },
        )
        result.nodes_created += int(created)
        result.nodes_reused += int(not created)
        dependency_nodes[dependency.pk] = node

    # --- edges from recorded relations -------------------------------------
    dep_relations = DependencyRelation.objects.using(db).select_related(
        "from_dependency", "to_dependency", "to_asset"
    )
    if session_id is not None:
        dep_relations = dep_relations.filter(session_id=session_id)

    for relation in dep_relations.iterator():
        source = dependency_nodes.get(relation.from_dependency_id)
        if source is None:
            continue
        if relation.to_dependency_id:
            target = dependency_nodes.get(relation.to_dependency_id)
            kind = (
                GraphEdge.RelationType.DEPENDS_ON
                if relation.relation_type == DependencyRelation.RelationType.DEPENDS_ON
                else GraphEdge.RelationType.PROVIDES
            )
        else:
            target = asset_nodes.get(relation.to_asset_id)
            kind = GraphEdge.RelationType.PROVIDES
        if target is None:
            continue
        if _upsert_edge(
            db, session_id, source, target, kind,
            {"why": "recorded dependency relation",
             "detail": relation.detail or "",
             "from": relation.relation_type},
        ):
            result.edges_created += 1

    # --- edges from recorded asset relations -------------------------------
    asset_relations = AssetRelation.objects.using(db).select_related(
        "from_asset", "to_asset"
    )
    if session_id is not None:
        asset_relations = asset_relations.filter(session_id=session_id)

    mapping = {
        AssetRelation.RelationType.CONTAINS: GraphEdge.RelationType.CONTAINS,
        AssetRelation.RelationType.DEPENDS: GraphEdge.RelationType.DEPENDS_ON,
        AssetRelation.RelationType.CONTEXT: GraphEdge.RelationType.CO_LOCATED,
        AssetRelation.RelationType.RELATE: GraphEdge.RelationType.RELATES_TO,
    }
    for relation in asset_relations.iterator():
        source = asset_nodes.get(relation.from_asset_id)
        target = asset_nodes.get(relation.to_asset_id)
        if source is None or target is None:
            continue
        if _upsert_edge(
            db, session_id, source, target,
            mapping.get(relation.relation_type, GraphEdge.RelationType.RELATES_TO),
            {"why": "recorded asset relation", "detail": relation.description or ""},
        ):
            result.edges_created += 1

    # --- edges from observation: file uses what was found in it ------------
    occurrences = AssetOccurrence.objects.using(db).select_related("asset", "finding")
    if session_id is not None:
        occurrences = occurrences.filter(asset__session_id=session_id)
    if scan_job is not None:
        occurrences = occurrences.filter(scan_job=scan_job)

    for occurrence in occurrences.iterator():
        asset_node = asset_nodes.get(occurrence.asset_id)
        if asset_node is None:
            continue
        path = occurrence.finding.raw_finding.source_path or occurrence.finding.raw_finding.location
        if not path:
            continue
        file_node = file_nodes.get(_file_identity(path))
        if file_node is None:
            continue
        relation = _FILE_TO_ASSET.get(asset_node.node_type, GraphEdge.RelationType.USES)
        if _upsert_edge(
            db, session_id, file_node, asset_node, relation,
            {"why": "observed in this file", "path": path,
             "location": occurrence.location or ""},
        ):
            result.edges_created += 1

    # --- edges from declaration: file uses the library it names -------------
    by_label: dict[str, list[GraphNode]] = {}
    for node in dependency_nodes.values():
        by_label.setdefault(node.label.lower(), []).append(node)

    for identity, library in library_mentions:
        file_node = file_nodes.get(identity)
        if file_node is None:
            continue
        named = library.split()[0].lower()
        for node in by_label.get(named, []):
            if _upsert_edge(
                db, session_id, file_node, node, GraphEdge.RelationType.USES,
                {"why": "the file names this library", "named": library},
            ):
                result.edges_created += 1
            break

    return result
