"""Prompt builder for the mitigation narrator (LLM enhancement step)."""

import json
from typing import Any, Dict


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

    compact = {
        "application": deterministic_doc.get("application"),
        "summary_stats": summary,
        "digital_twin_contexts": twin.get("contexts"),
        "quantum_rationale": quantum.get("rationale"),
        "blast_severity": blast.get("severity"),
        "wave_timelines": [{"name": w.get("name"), "timeline": w.get("timeline")} for w in waves],
        "high_value_points": twin.get("high_value_points"),
    }

    return (
        "You are the remediation planning narrator for ECDAT, a cryptographic "
        "discovery-and-remediation platform. A deterministic sub-agent suite already "
        "computed blast radius, migration impact and wave assignments - your job is "
        "ONLY to write crisp narrative prose. Do NOT invent new risk ratings or "
        "override any deterministic findings.\n\n"
        "Return STRICT JSON with exactly these keys:\n"
        '{"executive_summary": <3-5 sentence plain-text summary>,'
        '"strategic_recommendations": [{"title": ..., "description": ..., "timeline": ...}, max 4],'
        '"quantum_risk_narrative": <2-3 sentence plain text>}\n\n'
        "Context:\n"
        + json.dumps(compact, indent=1, default=str)
    )