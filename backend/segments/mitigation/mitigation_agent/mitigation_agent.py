"""MitigationAgent orchestrator.

Runs the sub-agent suite (blast radius, migration impact, suggestions) over a
run bundle, then optionally lets the NarratorAgent polish prose via Gemini.
The full document is deterministic-first: LLM output never alters risk
decisions, only narrative/summary text.
"""

from datetime import datetime, timezone
from typing import Any, Dict

from . import rules
from .llm_provider import get_mitigation_provider

_PRIORITY_WAVES: Dict[str, int] = {1: "Wave 1", 2: "Wave 2", 3: "Wave 3"}


class MitigationAgent:
    """Turn a completed analysis run bundle into a mitigation document."""

    def __init__(self, use_llm: bool = True):
        self._provider = get_mitigation_provider() if use_llm else None

    def generate(self, bundle: Dict[str, Any]) -> Dict[str, Any]:
        assets = list(bundle.get("assets") or [])

        for asset in assets:
            asset["service"] = asset.get("service") or rules.service_for_asset(asset)
            blast = rules.compute_blast_radius(asset, bundle)
            impact = rules.compute_migration_impact(asset)
            wave = rules.migration_wave_for(asset, blast)
            asset["blast"] = blast
            asset["impact"] = impact
            asset["wave"] = wave
            asset["suggestions"] = rules.suggestions_for(asset, blast, impact)
            asset["recommended_action"] = rules.recommended_action_for(asset)

        doc = self._assemble(bundle, assets)
        narration = {}
        if self._provider is not None:
            narration = self._provider.enhance(doc) or {}

        replacements = narration.get("code_replacements") or []
        replacements_by_asset = {
            str(item.get("asset_id")): item
            for item in replacements
            if item.get("asset_id")
        }
        for row in doc["rows"]:
            replacement = replacements_by_asset.get(str(row.get("asset_id") or row.get("id")))
            if replacement:
                row["code_replacement"] = replacement

        doc["executive_summary"] = narration.get("executive_summary") or self._default_summary(assets)
        doc["quantum_risk_narrative"] = narration.get("quantum_risk_narrative") or self._default_quantum_note(bundle, assets)
        doc["strategic_recommendations"] = narration.get("strategic_recommendations") or (
            doc.get("recommendations") or []
        )[:4]
        doc["ai_context"] = {
            "model_used": narration.get("model_used"),
            "enhanced": bool(narration.get("executive_summary")),
            "engine": "deterministic-rules + LLM narrator"
            if self._provider is not None
            else "deterministic-rules (no LLM configured)",
        }
        doc["generated_at"] = datetime.now(timezone.utc).isoformat()
        return doc

    def _assemble(self, bundle: Dict[str, Any], assets: list) -> Dict[str, Any]:
        twin = rules.digital_twin(bundle)
        quantum = rules.quantum_risk(bundle)
        blast_summary = rules.blast_radius_summary(bundle)
        rows = [
            {
                "id": a.get("id"),
                "asset_id": a.get("asset_id"),
                "algorithm": rules.normalize_algorithm(a.get("algorithm")) or "Unknown",
                "family": a.get("family") or "",
                "algorithm_category": a.get("algorithm_category") or "UNKNOWN",
                "classical_security": a.get("classical_security") or "UNKNOWN",
                "overall_risk": a.get("overall_risk") or "UNKNOWN",
                "migration_priority": a.get("migration_priority") or "LOW",
                "quantum_vulnerable": bool(a.get("quantum_vulnerable")),
                "hndl_risk": a.get("hndl_risk") or "",
                "service": a.get("service"),
                "blast_radius": a.get("blast"),
                "migration_impact": a.get("impact"),
                "migration_wave": a.get("wave"),
                "suggestions": a.get("suggestions"),
                "recommended_action": a.get("recommended_action"),
                "source_context": self._source_context(a),
            }
            for a in assets
        ]
        rows.sort(
            key=lambda r: (
                rules.PRIORITY_RANK.get((r["migration_priority"] or "").upper(), 50),
                rules.SEVERITY_RANK.get((r["blast_radius"] or {}).get("severity", "LOW"), 3),
                str(r["id"]),
            )
        )

        waves = []
        for i, wave_def in enumerate(rules.WAVE_DEFS, start=1):
            wave_rows = [r for r in rows if r.get("migration_wave") == i]
            waves.append(
                {
                    **wave_def,
                    "assets": [r.get("asset_id") or r.get("id") for r in wave_rows],
                    "asset_count": len(wave_rows),
                }
            )

        stats = self._stats(assets, rows)
        recommendations = rules.baseline_recommendations(bundle)

        return {
            "application": bundle.get("application") or "ECDAT inventory",
            "repository": bundle.get("repository") or {},
            "summary": stats,
            "digital_twin": twin,
            "quantum_risk": quantum,
            "blast_radius": blast_summary,
            "rows": rows,
            "waves": waves,
            "recommendations": recommendations,
        }

    @staticmethod
    def _source_context(asset: Dict[str, Any]) -> Dict[str, Any]:
        cbom = asset.get("cbom_asset") or {}
        location = cbom.get("location") or {}
        explainability = cbom.get("explainability") or {}
        evidence = cbom.get("evidence") or cbom.get("code") or ""
        if not evidence:
            field_evidence = explainability.get("field_evidence") or explainability.get("evidence") or []
            evidence = next(
                (
                    item.get("snippet")
                    for item in field_evidence
                    if isinstance(item, dict) and item.get("snippet")
                ),
                "",
            )
        if not evidence:
            return {}
        return {
            "file": location.get("file"),
            "line": location.get("line"),
            "evidence": str(evidence)[:8000],
        }

    @staticmethod
    def _stats(assets: list, rows: list) -> Dict[str, Any]:
        by_priority = {"URGENT": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        by_risk = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        qv = hndl = wave_high = 0
        for r in rows:
            (r.get("migration_priority") or "LOW").upper()
            key_priority = (r.get("migration_priority") or "LOW").upper()
            if key_priority in by_priority:
                by_priority[key_priority] += 1
            key_risk = (r.get("overall_risk") or "UNKNOWN").upper()
            if key_risk in by_risk:
                by_risk[key_risk] += 1
            if r.get("quantum_vulnerable"):
                qv += 1
            if (r.get("hndl_risk") or "").upper() in ("HIGH", "CRITICAL"):
                hndl += 1
            if r.get("blast_radius", {}).get("severity") in ("CRITICAL", "HIGH"):
                wave_high += 1

        effort_high = sum(1 for r in rows if (r.get("migration_impact") or {}).get("effort") == "HIGH")
        effort_med = sum(1 for r in rows if (r.get("migration_impact") or {}).get("effort") == "MEDIUM")
        effort_quarters = max(1, effort_high + (effort_med + 1) // 2)

        return {
            "assets": len(rows),
            "by_priority": by_priority,
            "by_risk": by_risk,
            "urgent": by_priority["URGENT"],
            "critical_risk": by_risk["CRITICAL"],
            "high_risk": by_risk["HIGH"],
            "quantum_vulnerable": qv,
            "hndl_exposed": hndl,
            "wave1": sum(1 for r in rows if r.get("migration_wave") == 1),
            "wave2": sum(1 for r in rows if r.get("migration_wave") == 2),
            "wave3": sum(1 for r in rows if r.get("migration_wave") == 3),
            "effort_estimate_quarters": effort_quarters,
            "has_assets": len(assets) > 0,
        }

    @staticmethod
    def _default_summary(rows: list) -> str:
        if not rows:
            return "No cryptographic assets were found; no remediation is required."
        urgent = sum(1 for r in rows if (r.get("migration_priority") or "").upper() == "URGENT")
        qv = sum(1 for r in rows if r.get("quantum_vulnerable"))
        return (
            f"The estate ships {len(rows)} cryptographic asset(s) across "
            f"{len({r.get('service') for r in rows}) if rows else 0} service(s). "
            f"{urgent} are urgent and "
            f"{qv} are post-quantum vulnerable. The remediation plan stages these into "
            "three waves: urgent HNDL/PQC triage first, broad public-key migration second, "
            "and symmetric/digest hardening last."
        )

    @staticmethod
    def _default_quantum_note(bundle: Dict[str, Any], rows: list) -> str:
        qv = sum(1 for r in rows if r.get("quantum_vulnerable"))
        if qv == 0:
            return (
                "No public-key primitives with post-quantum vulnerability were found. "
                "Re-run after new scans; symmetric and hash assets already carry a "
                "Grover-safety margin."
            )
        return (
            f"{qv} post-quantum vulnerable primitive(s) exist. Because a CRQC can "
            "retroactively decrypt captured ciphertext and forge signatures, "
            "recommendations bias toward rotating exposed keys now and staging "
            "ML-KEM/ML-DSA migration before reliance on long-term confidentiality."
        )