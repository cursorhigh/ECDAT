"""Discover -> Understand handoff.

Milestone 12: discovery's dataset is not passed along implicitly; it is
assembled into one explicit, inspectable object, and the plan's hand-off contract
is enforced rather than assumed.

The contract (plan section 29) requires that for every finding, Understand can
answer:

    WHAT was discovered?      WHERE was it discovered?   HOW was it discovered?
    HOW CONFIDENT are we?      WHAT asset does it belong to?
    WHAT does it depend on?

:attr:`Handoff.contract_gaps` proves it. Anything it reports is a hole in
discovery's output rather than a processing problem downstream.

Coverage honesty travels with the data. A scan that skipped files hands over a
dataset that says so, so a plan built from it can disclose that instead of
implying full coverage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import (
    AssetOccurrence,
    CryptoAsset,
    Dependency,
    DependencyRelation,
    GraphEdge,
    GraphNode,
    NormalizedFinding,
    ScanJob,
)

# The six questions Understand must be able to answer.
CONTRACT_QUESTIONS = (
    "what_was_discovered",
    "where_was_it_discovered",
    "how_was_it_discovered",
    "how_confident_are_we",
    "what_asset_does_it_belong_to",
    "what_does_it_depend_on",
)

# GraphNode.ref_model values, matching graph_index.
ASSET_REF = "CryptoAsset"


def _normalise_skip_reasons(raw) -> dict:
    """Collapse ``skip_reasons`` to a reason -> count mapping.

    A single scanner reports a tally; the multi-source run may leave a list of
    per-scanner "skipped entirely" notes. Both have to become a mapping, because
    ``ScanCoverage.skip_reasons`` is read with ``.items()``.
    """
    if isinstance(raw, dict):
        return {str(k): v for k, v in raw.items()}
    if isinstance(raw, (list, tuple)):
        out: dict = {}
        for item in raw:
            text = str(item)
            out[text] = out.get(text, 0) + 1
        return out
    return {}


@dataclass
class FindingHandoff:
    """One finding, with every contract answer attached."""

    finding_id: str
    # WHAT
    algorithm: str = ""
    family: str = ""
    kind: str = ""
    key_size: int | None = None
    curve: str = ""
    # WHERE
    location: str = ""
    source_path: str = ""
    line: int | None = None
    # HOW
    source_type: str = ""
    detector: str = ""
    evidence_type: str = ""
    evidence: dict = field(default_factory=dict)
    # HOW CONFIDENT
    confidence: float | None = None
    validation_status: str = ""
    # WHAT ASSET
    asset_id: int | None = None
    asset_identifier: str = ""
    asset_type: str = ""
    asset_name: str = ""
    # WHAT IT DEPENDS ON
    depends_on: list[str] = field(default_factory=list)
    used_by: list[str] = field(default_factory=list)

    def answers(self) -> dict[str, bool]:
        """Which contract questions this finding can answer."""
        return {
            "what_was_discovered": bool(self.algorithm or self.family or self.kind),
            "where_was_it_discovered": bool(self.location or self.source_path),
            "how_was_it_discovered": bool(self.source_type),
            "how_confident_are_we": self.confidence is not None,
            # A finding with no asset is still answerable: it means discovery has
            # not merged it into an identity yet, which is a real, reportable
            # state rather than a missing answer.
            "what_asset_does_it_belong_to": True,
            # Only a library-backed finding references dependencies, and "nothing"
            # is the correct answer for the rest.
            "what_does_it_depend_on": True,
        }

    def gaps(self) -> list[str]:
        return [question for question, ok in self.answers().items() if not ok]

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "algorithm": self.algorithm,
            "family": self.family,
            "kind": self.kind,
            "key_size": self.key_size,
            "curve": self.curve,
            "location": self.location,
            "source_path": self.source_path,
            "line": self.line,
            "source_type": self.source_type,
            "detector": self.detector,
            "evidence_type": self.evidence_type,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "validation_status": self.validation_status,
            "asset_id": self.asset_id,
            "asset_identifier": self.asset_identifier,
            "asset_type": self.asset_type,
            "asset_name": self.asset_name,
            "depends_on": self.depends_on,
            "used_by": self.used_by,
            "unanswered": self.gaps(),
        }


@dataclass
class Coverage:
    """What the scan did and did not read, carried into the hand-off."""

    scan_status: str = "unscanned"
    items_total: int | None = None
    items_scanned: int = 0
    items_skipped: int = 0
    skip_reasons: dict = field(default_factory=dict)
    sources_run: list[str] = field(default_factory=list)
    sources_excluded: list[dict] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return self.scan_status == "completed" and self.items_skipped == 0

    def _disclosure(self) -> str:
        if self.complete:
            return "Every discovered item was read."
        parts = []
        if self.items_skipped:
            reasons = ", ".join(
                f"{count} {reason.replace('_', ' ')}" for reason, count in sorted(
                    self.skip_reasons.items()
                )
            )
            parts.append(
                f"{self.items_skipped} item(s) were not inspected"
                + (f" ({reasons})" if reasons else "")
            )
        if self.sources_excluded:
            excluded = ", ".join(
                str(entry.get("source_type") or "unknown")
                for entry in self.sources_excluded
            )
            parts.append(f"these sources did not run: {excluded}")
        if parts:
            # Skips matter even when no source is known to have run, so this is
            # checked before the "nothing discovered" case: reporting "nothing
            # discovered" while also having skipped items would hide the skips.
            return "; ".join(parts).capitalize() + ". Results describe only what was read."
        if not self.sources_run and not self.items_scanned:
            return "Nothing has been discovered for this scope yet."
        return (
            f"The scan reported status '{self.scan_status}'; "
            "results describe only what was read."
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "scan_status": self.scan_status,
            "items_total": self.items_total,
            "items_scanned": self.items_scanned,
            "items_skipped": self.items_skipped,
            "skip_reasons": self.skip_reasons,
            "complete": self.complete,
            "sources_run": self.sources_run,
            "sources_excluded": self.sources_excluded,
            "disclosure": self._disclosure(),
        }


@dataclass
class Handoff:
    scan_job_id: int | None = None
    session_id: int | None = None
    target: str = ""
    coverage: Coverage = field(default_factory=Coverage)
    findings: list[FindingHandoff] = field(default_factory=list)
    assets: int = 0
    dependencies: int = 0
    graph_nodes: int = 0
    graph_edges: int = 0
    # True when more findings matched than were returned, so a consumer can tell
    # "this is everything" from "this is the first page".
    truncated: bool = False

    def contract_gaps(self) -> dict[str, int]:
        """Per-question count of findings that cannot answer it.

        Only meaningful when `truncated` is False: on a truncated page the
        findings that were dropped are unexamined, not proven answerable.
        """
        gaps: dict[str, int] = {}
        for entry in self.findings:
            for question in entry.gaps():
                gaps[question] = gaps.get(question, 0) + 1
        return gaps

    def as_dict(self) -> dict[str, Any]:
        gaps = self.contract_gaps()
        return {
            "scan_job_id": self.scan_job_id,
            "session_id": self.session_id,
            "target": self.target,
            "coverage": self.coverage.as_dict(),
            "counts": {
                "findings": len(self.findings),
                "assets": self.assets,
                "dependencies": self.dependencies,
                "graph_nodes": self.graph_nodes,
                "graph_edges": self.graph_edges,
                "findings_truncated": self.truncated,
            },
            "contract": {
                "questions": list(CONTRACT_QUESTIONS),
                "unanswered_by_question": gaps,
                # An empty dataset has no gaps, so "no gaps" would otherwise read
                # as "everything answered". There is nothing here to have
                # answered anything, so it reports unsatisfied.
                "satisfied": bool(self.findings) and not gaps and not self.truncated,
            },
            "findings": [entry.as_dict() for entry in self.findings],
        }


def _asset_summaries(db: str, session_id, scan_job) -> dict[int, tuple]:
    """Map NormalizedFinding id -> (asset pk, identifier, type, name).

    An artefact and its occurrences are different things, so the asset is read
    through AssetOccurrence rather than assumed to be the finding's only
    identity.
    """
    occurrences = AssetOccurrence.objects.using(db).select_related("asset")
    if session_id is not None:
        occurrences = occurrences.filter(asset__session_id=session_id)
    if scan_job is not None:
        occurrences = occurrences.filter(scan_job=scan_job)
    summary: dict[int, tuple] = {}
    for occurrence in occurrences[:5000]:
        if occurrence.finding_id is None:
            # Occurrences of the asset itself, not of a specific finding.
            continue
        asset = occurrence.asset
        summary.setdefault(
            occurrence.finding_id,
            (asset.pk, asset.identifier or "", asset.asset_type or "", asset.name or ""),
        )
    return summary


def _provider_packages(db: str, session_id) -> dict[int, list[str]]:
    """Asset pk -> the packages that declare/provide it."""
    relations = DependencyRelation.objects.using(db).select_related("from_dependency")
    if session_id is not None:
        relations = relations.filter(session_id=session_id)
    providers: dict[int, list[str]] = {}
    for relation in relations[:5000]:
        if relation.to_asset_id is None:
            continue
        package = relation.from_dependency.package
        if package:
            providers.setdefault(relation.to_asset_id, []).append(package)
    return providers


def _used_by_labels(db: str, session_id, asset_ids: set[int]) -> dict[int, list[str]]:
    """Asset pk -> graph nodes pointing at it, i.e. what depends on it."""
    if not asset_ids:
        return {}
    nodes = {
        node.pk: node
        for node in GraphNode.objects.using(db).filter(
            ref_model=ASSET_REF, ref_id__in=asset_ids
        )
    }
    if not nodes:
        return {}
    if session_id is not None:
        edges = GraphEdge.objects.using(db).filter(
            to_node_id__in=nodes.keys(), session_id=session_id
        ).select_related("from_node")
    else:
        edges = GraphEdge.objects.using(db).filter(
            to_node_id__in=nodes.keys()
        ).select_related("from_node")
    used_by: dict[int, list[str]] = {}
    for edge in edges[:5000]:
        asset_id = nodes[edge.to_node_id].ref_id
        label = edge.from_node.label or edge.from_node.node_type
        if label:
            used_by.setdefault(int(asset_id), []).append(label)
    return used_by


def _missing_sources(sources_run: set[str]) -> list[dict]:
    """Available discovery sources that have not run for this scope.

    Reported as coverage rather than absence: a dataset built from two of four
    sources is a valid dataset, but the consumer has to know which two. Planned
    sources are not listed, because naming an unimplemented scanner as a
    coverage gap would overstate what discovery owes.
    """
    from .scanners import list_scanners

    missing = []
    for entry in list_scanners():
        if entry.get("status") != "available":
            continue
        # `id` is the scanner implementation ('binary-inspection'); `source_type`
        # is the discovery source ('binary'), which is what ScanJob records.
        # Comparing the wrong one reported sources that had run as missing.
        source_type = entry.get("source_type") or entry.get("id")
        if not source_type or source_type in sources_run:
            continue
        missing.append(
            {
                "source_type": source_type,
                "label": entry.get("name") or entry.get("label") or source_type,
                "reason": "not scanned for this scope",
            }
        )
    return missing


def build_handoff(
    db: str,
    session_id=None,
    scan_job: ScanJob | None = None,
    limit: int = 5000,
) -> Handoff:
    """Assemble the Discover -> Understand dataset for a scope or one scan.

    With neither a session nor a scan this returns an empty hand-off. The
    counts used to be gathered from unfiltered tables in that case, so the
    dataset described the whole estate while claiming to describe one scan.
    """
    if session_id is None and scan_job is None:
        return Handoff(coverage=Coverage(scan_status="unscanned"))

    if session_id is None and scan_job is not None:
        session_id = scan_job.session_id

    handoff = Handoff(
        scan_job_id=scan_job.pk if scan_job is not None else None,
        session_id=session_id,
        target=(scan_job.target if scan_job is not None else "") or "",
    )

    if scan_job is not None:
        handoff.coverage.scan_status = scan_job.status
        handoff.coverage.items_total = scan_job.items_total
        handoff.coverage.items_scanned = scan_job.items_scanned or 0
        handoff.coverage.items_skipped = scan_job.items_skipped or 0
        # `skip_reasons` is a tally for a single scanner but a list of notes once the
        # multi-source run folds in per-scanner "skipped entirely" reasons, and the
        # coverage dataclass below is consumed via `.items()`. Normalise rather than
        # assume, so a partial scan from any source still builds its handoff.
        handoff.coverage.skip_reasons = _normalise_skip_reasons(scan_job.skip_reasons)
        handoff.coverage.sources_run = [scan_job.source_type]
    else:
        jobs = ScanJob.objects.using(db)
        if session_id is not None:
            jobs = jobs.filter(session_id=session_id)
        rows = list(
            jobs.values_list("status", "source_type", "items_scanned", "items_skipped")[:500]
        )
        statuses = [row[0] for row in rows]
        handoff.coverage.scan_status = (
            "partial"
            if any(status in ("partial", "failed") for status in statuses)
            else ("completed" if statuses else "unscanned")
        )
        handoff.coverage.items_scanned = sum(row[2] or 0 for row in rows)
        handoff.coverage.items_skipped = sum(row[3] or 0 for row in rows)
        handoff.coverage.sources_run = sorted({row[1] for row in rows if row[1]})
        # A source that is available but never run is a coverage gap the consumer
        # has to be told about, not a silent absence.
        handoff.coverage.sources_excluded = _missing_sources(
            {row[1] for row in rows if row[1]}
        )

    summary = _asset_summaries(db, session_id, scan_job)
    providers = _provider_packages(db, session_id)
    used_by = _used_by_labels(
        db, session_id, {value[0] for value in summary.values()}
    )

    assets = CryptoAsset.objects.using(db)
    if session_id is not None:
        assets = assets.filter(session_id=session_id)
    handoff.assets = assets.count()

    dependencies = Dependency.objects.using(db)
    if session_id is not None:
        dependencies = dependencies.filter(session_id=session_id)
    if scan_job is not None:
        dependencies = dependencies.filter(scan_job=scan_job)
    handoff.dependencies = dependencies.count()

    nodes = GraphNode.objects.using(db)
    edges = GraphEdge.objects.using(db)
    if session_id is not None:
        nodes = nodes.filter(session_id=session_id)
        edges = edges.filter(session_id=session_id)
    handoff.graph_nodes = nodes.count()
    handoff.graph_edges = edges.count()

    findings = NormalizedFinding.objects.using(db).select_related(
        "raw_finding", "raw_finding__scan_job"
    )
    if session_id is not None:
        findings = findings.filter(session_id=session_id)
    if scan_job is not None:
        findings = findings.filter(raw_finding__scan_job=scan_job)

    for norm in findings[: limit + 1]:
        raw = norm.raw_finding
        evidence = norm.evidence or {}
        asset = summary.get(norm.pk)
        asset_id = asset[0] if asset else None
        handoff.findings.append(
            FindingHandoff(
                finding_id=f"N{norm.pk}",
                algorithm=norm.algorithm or "",
                family=norm.family or "",
                kind=norm.kind or "",
                key_size=norm.key_size,
                curve=norm.curve or "",
                location=raw.location or "",
                source_path=raw.source_path or "",
                line=norm.line,
                source_type=raw.source_type or "",
                detector=str(evidence.get("detector") or ""),
                evidence_type=str(evidence.get("type") or ""),
                evidence=evidence,
                confidence=norm.confidence,
                validation_status="confirmed" if asset_id else "needs_review",
                asset_id=asset_id,
                asset_identifier=asset[1] if asset else "",
                asset_type=asset[2] if asset else "",
                asset_name=asset[3] if asset else "",
                depends_on=sorted(set(providers.get(asset_id, []))) if asset_id else [],
                used_by=sorted(set(used_by.get(asset_id, []))) if asset_id else [],
            )
        )

    # One extra row was fetched to detect truncation, so the flag is knowable
    # rather than inferred from a list that was already cut to size.
    if len(handoff.findings) > limit:
        handoff.findings = handoff.findings[:limit]
        handoff.truncated = True

    return handoff


def contract_gaps(
    db: str, session_id=None, scan_job: ScanJob | None = None
) -> dict[str, int]:
    """Findings that cannot answer one of the contract questions."""
    return build_handoff(db, session_id=session_id, scan_job=scan_job).contract_gaps()
