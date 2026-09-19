"""Mitigation agent package.

Multi-agent orchestration that turns a completed analysis run's CBOM + risk
output into a prioritized remediation / migration plan:

* BlastRadiusAgent     - which services/exposures each failure reaches.
* MigrationImpactAgent - predicted effort, compatibility and PQC replacement.
* SuggestionAgent      - actionable, ordered next steps per asset.
* NarratorAgent        - optional Gemini narrative enhancement (deterministic
                         fallback when no API key or on any failure).

The orchestrator ``MitigationAgent.generate`` consumes a plain-dict run bundle
(assembled by ``mitigation.planner``) and returns a full mitigation document.
It never raises; every sub-agent degrades to deterministic rules.
"""

from .mitigation_agent import MitigationAgent

__all__ = ["MitigationAgent"]