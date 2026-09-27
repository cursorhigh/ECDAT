"""CBOM assembly and export.

Builds a Cryptographic Bill of Materials from what discovery recorded, in any
of three shapes:

* ``ecdat``          - ECDAT's native document, the richest form
* ``cyclonedx-json`` - CycloneDX 1.6, for other tools
* ``cyclonedx-xml``  - the same BOM as XML

The exporter is deliberately the only place that decides what a CBOM contains.
It reads from the authoritative tables rather than from an analysis run's cached
document when a run is supplied, so an export always reflects current discovery
state instead of a snapshot that may be stale.
"""

from __future__ import annotations

import json
from typing import Any

from core.modes import active_db
from core.sessions import thread_session_id

from . import cyclonedx

FORMATS = ("ecdat", "cyclonedx-json", "cyclonedx-xml")

_CONTENT_TYPES = {
    "ecdat": "application/json",
    "cyclonedx-json": "application/vnd.cyclonedx+json",
    "cyclonedx-xml": "application/vnd.cyclonedx+xml",
}


class CBOMUnavailable(Exception):
    """No CBOM can be produced for the requested scope (nothing discovered)."""


class UnsupportedCBOMFormat(Exception):
    """The requested serialisation is not one this build produces."""


def _native_document(db: str, session_id, run=None) -> dict[str, Any]:
    """Assemble the native CBOM from recorded assets."""
    from datetime import datetime, timezone

    from core.sessions import scope
    from segments.scraping.discovery.models import AssetOccurrence, CryptoAsset, Dependency

    # `scope` yields nothing when no session is selected. Filtering by hand with
    # "if a session is set" meant an export taken while looking at one scan could
    # contain every other scan's assets.
    assets = scope(CryptoAsset.objects.using(db), session_id)
    dependencies = scope(Dependency.objects.using(db), session_id)
    if run is not None:
        assets = assets.filter(
            occurrences__scan_job=run.scan_job_id
        ).distinct()
        dependencies = dependencies.filter(scan_job=run.scan_job_id)

    occurrences = AssetOccurrence.objects.using(db).filter(asset__in=assets)
    if run is not None:
        occurrences = occurrences.filter(scan_job=run.scan_job_id)
    # Evidence lives on the finding, not the asset: an asset is a merged identity
    # and deliberately carries no single observation of its own.
    sighting_by_asset: dict[int, dict[str, Any]] = {}
    for occurrence in occurrences.select_related("finding")[:5000]:
        finding = occurrence.finding
        sighting_by_asset.setdefault(
            occurrence.asset_id,
            {
                "location": occurrence.location or finding.raw_finding.location or "",
                "line": occurrence.line,
                "evidence": finding.evidence or {},
            },
        )

    crypto_assets: list[dict[str, Any]] = []
    for asset in assets[:5000]:
        sighting = sighting_by_asset.get(asset.pk, {})
        evidence = sighting.get("evidence") or {}
        crypto_assets.append(
            {
                "asset_id": asset.pk,
                "identifier": asset.identifier,
                "name": asset.name,
                "kind": asset.asset_type,
                "asset_type": asset.asset_type,
                "family": asset.family or "",
                "algorithm": asset.algorithm or "",
                "key_size": asset.key_size,
                "curve": asset.curve or "",
                "protocol": asset.protocol or "",
                "library": asset.library or "",
                "library_version": asset.library_version or "",
                "source_type": asset.source_type or "",
                "location": sighting.get("location") or asset.location or "",
                "line": sighting.get("line"),
                "validation_status": _validation_status(asset),
                "confidence": 1.0,
                "evidence_type": str(evidence.get("type") or ""),
                "detector": str(evidence.get("detector") or ""),
                "evidence": evidence,
            }
        )

    for dependency in dependencies.filter(is_crypto=True)[:1000]:
        # Identity is `<ecosystem>:<package>`, matching the unified graph's node
        # key with its type prefix stripped, so a graph edge resolves to a real
        # component in the exported BOM.
        identity = f"{dependency.ecosystem or 'unknown'}:{dependency.package}"
        crypto_assets.append(
            {
                "asset_id": f"dep-{dependency.pk}",
                "identifier": identity,
                "name": dependency.package,
                "kind": "library",
                "asset_type": "library",
                "family": dependency.family or "",
                "algorithm": "",
                "library": dependency.package,
                "library_version": dependency.version or "",
                "location": dependency.location or "",
                "validation_status": "confirmed" if dependency.is_crypto else "needs_review",
                "confidence": 1.0,
                "evidence_type": "manifest_entry",
            }
        )

    families: dict[str, int] = {}
    for entry in crypto_assets:
        families[entry["family"] or "unknown"] = families.get(entry["family"] or "unknown", 0) + 1

    repository = (run.repository if run is not None and run.repository else {}) or {}
    target = ""
    if run is not None and run.scan_job_id:
        from segments.scraping.discovery.models import ScanJob

        job = ScanJob.objects.using(db).filter(pk=run.scan_job_id).first()
        target = (job.target if job else "") or ""
    name = repository.get("name") or target or "ECDAT inventory"

    return {
        "format": "ECDAT-CBOM",
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repository": {"name": name, "url": repository.get("url", "") or ""},
        "summary": {
            "total_assets": len(crypto_assets),
            "confirmed_assets": sum(
                1 for e in crypto_assets if e["validation_status"] == "confirmed"
            ),
            "partial_assets": sum(
                1 for e in crypto_assets if e["validation_status"] == "partial"
            ),
            "needs_review_assets": sum(
                1 for e in crypto_assets if e["validation_status"] == "needs_review"
            ),
            "invalid_assets": sum(
                1 for e in crypto_assets if e["validation_status"] == "invalid"
            ),
            "by_family": families,
        },
        "crypto_assets": crypto_assets,
    }


def _validation_status(asset) -> str:
    """Map a recorded asset onto the contract's vocabulary.

    A weak or dated certificate is `needs_review`, never `invalid`: nothing
    here declares an artefact broken, it records what was observed and how
    confident discovery is about it.
    """
    if asset.inventory_status == "retired":
        return "partial"
    return "confirmed"


def _dependency_edges(db: str, session_id) -> list[tuple[str, str]]:
    """Graph edges, expressed as bom-refs, for the CycloneDX dependency graph.

    Read from the unified relationship graph, so the exported dependency shape is
    the same one the Graph tab shows rather than a second, divergent answer.

    A node's bom-ref is its key with the node type stripped, which is exactly
    what ``_native_document`` uses as the asset identifier. That shared identity
    is what lets an edge point at a component that actually exists in the BOM;
    a mismatch would silently produce dangling references.
    """
    from core.sessions import scope
    from segments.scraping.discovery.models import GraphEdge, GraphNode

    nodes = scope(GraphNode.objects.using(db), session_id)
    edges = scope(GraphEdge.objects.using(db), session_id)

    prefixes = tuple(f"{choice}:" for choice in GraphNode.NodeType.values)
    ref_by_node: dict[int, str] = {}
    for node in nodes.only("id", "key", "node_type"):
        for prefix in prefixes:
            if node.key.startswith(prefix):
                ref_by_node[node.id] = f"urn:ecdat:asset:{node.key[len(prefix):]}"
                break

    pairs: list[tuple[str, str]] = []
    for edge in edges.only("id", "from_node_id", "to_node_id")[:5000]:
        source = ref_by_node.get(edge.from_node_id)
        target = ref_by_node.get(edge.to_node_id)
        if source and target:
            pairs.append((source, target))
    return pairs


def build_export(output_format: str, db: str | None = None, session_id=None,
                 run=None) -> tuple[bytes, str, str]:
    """Return (body, content_type, filename) for the requested format."""
    if output_format not in FORMATS:
        raise UnsupportedCBOMFormat(
            f"Unsupported format '{output_format}'. Use one of: {', '.join(FORMATS)}."
        )
    db = db or active_db()
    if session_id is None:
        session_id = thread_session_id()

    document = _native_document(db, session_id, run=run)
    if not document["crypto_assets"]:
        raise CBOMUnavailable(
            "No cryptographic assets have been discovered in this scope yet."
        )

    stem = "ecdat-cbom"
    if output_format == "ecdat":
        body = json.dumps(document, indent=2, ensure_ascii=False).encode("utf-8")
        return body, _CONTENT_TYPES["ecdat"], f"{stem}.json"

    edges = _dependency_edges(db, session_id)
    document_cyclonedx = cyclonedx.to_cyclonedx(document, dependency_edges=edges)

    if output_format == "cyclonedx-json":
        body = json.dumps(document_cyclonedx, indent=2, ensure_ascii=False).encode("utf-8")
        return body, _CONTENT_TYPES["cyclonedx-json"], f"{stem}.cdx.json"

    xml = cyclonedx.to_cyclonedx_xml(document_cyclonedx)
    return (
        xml.encode("utf-8"),
        _CONTENT_TYPES["cyclonedx-xml"],
        f"{stem}.cdx.xml",
    )
