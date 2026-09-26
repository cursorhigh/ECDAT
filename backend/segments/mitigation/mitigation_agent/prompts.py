"""Prompt builder for the mitigation narrator (LLM enhancement step)."""

import json
from typing import Any, Dict

from . import rules


def _replacement_catalog() -> Dict[str, Dict[str, str]]:
    return {
        algorithm: {
            "replacement": values[0],
            "category": values[1],
            "effort": values[2],
            "impact": values[3],
            "compatibility_risk": values[4],
            "reason": values[5],
        }
        for algorithm, values in rules._REPLACEMENTS.items()
    } | {
        "UNKNOWN": {
            "replacement": rules._UNKNOWN_REPLACEMENT[0],
            "category": rules._UNKNOWN_REPLACEMENT[1],
            "effort": rules._UNKNOWN_REPLACEMENT[2],
            "impact": rules._UNKNOWN_REPLACEMENT[3],
            "compatibility_risk": rules._UNKNOWN_REPLACEMENT[4],
            "reason": rules._UNKNOWN_REPLACEMENT[5],
        }
    }


def _code_context(row: Dict[str, Any]) -> Dict[str, Any]:
    context = row.get("source_context") or {}
    return {
        "asset_id": row.get("asset_id") or row.get("id"),
        "file": context.get("file"),
        "line": context.get("line"),
        "algorithm": row.get("algorithm"),
        "replacement": (row.get("migration_impact") or {}).get("replacement"),
        "evidence": context.get("evidence") or context.get("code") or "",
    }


def build_mitigation_prompt(deterministic_doc: Dict[str, Any]) -> str:
    """Build a compact prompt asking Gemini to polish narrative-only fields.

    The full deterministic plan is included for grounding; the model only returns
    narrative/summary fields, never risk decisions (those stay deterministic).
    """
    summary = deterministic_doc.get("summary") or {}
    twin = deterministic_doc.get("digital_twin") or {}
    quantum = deterministic_doc.get("quantum_risk") or {}
    blast = deterministic_doc.get("blast_radius") or {}
    waves = deterministic_doc.get("waves") or []
    rows = deterministic_doc.get("rows") or []

    compact = {
        "application": deterministic_doc.get("application"),
        "summary_stats": summary,
        "digital_twin_contexts": twin.get("contexts"),
        "quantum_rationale": quantum.get("rationale"),
        "blast_severity": blast.get("severity"),
        "wave_timelines": [{"name": w.get("name"), "timeline": w.get("timeline")} for w in waves],
        "high_value_points": twin.get("high_value_points"),
        "assets_requiring_code_replacement": [
            _code_context(row) for row in rows if row.get("source_context")
        ],
        "approved_replacement_catalog": _replacement_catalog(),
    }

    return (
        "You are the remediation planning narrator for ECDAT, a cryptographic "
        "discovery-and-remediation platform. A deterministic sub-agent suite already "
        "computed blast radius, migration impact and wave assignments - your job is "
        "write crisp narrative prose and, when source evidence is present, propose "
        "a minimal replacement code block. Do NOT invent new risk ratings, algorithms, "
        "or override any deterministic findings. The approved replacement catalog is "
        "authoritative. Use the exact replacement for each asset.\n\n"
        "Return STRICT JSON with exactly these keys:\n"
        '{"executive_summary": <3-5 sentence plain-text summary>,'
        '"strategic_recommendations": [{"title": ..., "description": ..., "timeline": ...}, max 4],'
        '"quantum_risk_narrative": <2-3 sentence plain text>,\n'
        '"code_replacements": [{"asset_id": ..., "file": ..., "language": ..., '
        '"replacement_algorithm": ..., "vulnerable_code": ..., "replacement_code": ..., '
        '"explanation": ...}, max 1 per asset]}\n\n'
        "For code_replacements, return an empty array when no source code/evidence is "
        "available. Do not fabricate missing code. Keep vulnerable_code grounded in "
        "the supplied evidence and make replacement_code a directly usable code block.\n\n"
        "Context:\n"
        + json.dumps(compact, indent=1, default=str)
    )