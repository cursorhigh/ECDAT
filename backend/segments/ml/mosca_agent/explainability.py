"""
MOSCA+ Explainability & Rationale Generator (explainability.py)

Generates deterministic, auditable human-readable rationales and policy summaries
strictly derived from Mosca inequality calculations without modifying any scores.
"""

from typing import Dict, Any


class MoscaExplainabilityBuilder:
    """
    Constructs explainability narratives for Mosca Theorem risk assessments.
    """

    @classmethod
    def build_explanation(
        cls,
        algorithm_name: str,
        s_crypto: float,
        variables: Dict[str, Any],
        timeline: Dict[str, Any],
        inequality_satisfied: bool,
        mosca_risk_index: float,
        posture: str,
        assumptions: Dict[str, Any],
    ) -> str:
        """
        Builds a comprehensive, deterministic explanation narrative.
        """
        X = variables.get("X_migration_time_years", 0.0)
        Y = variables.get("Y_data_lifetime_years", 0.0)
        Z = variables.get("Z_time_to_crqc_years", 0.0)
        X_plus_Y = variables.get("X_plus_Y", 0.0)
        delta_M = timeline.get("mosca_deficit_years", 0.0)
        crqc_year = assumptions.get("quantum_horizon_year", 2033)
        source = assumptions.get("quantum_horizon_source", "CONFIGURATION")
        must_start = timeline.get("must_start_by_year", 2026)
        is_overdue = timeline.get("is_overdue_to_start", False)

        if posture == "QUANTUM_RESILIENT" or s_crypto == 0.0:
            return (
                f"Algorithm {algorithm_name} is post-quantum secure or quantum-resilient "
                f"(cryptographic susceptibility: {s_crypto:.2f}). Mosca inequality X + Y > Z is not applicable."
            )

        if is_overdue:
            return (
                f"CRITICAL OVERDUE: For {algorithm_name}, required migration time X={X:.1f} yrs exceeds the "
                f"{Z:.1f} yrs remaining before projected {crqc_year} CRQC arrival (scenario source: {source}). "
                f"Migration should have commenced by {must_start:.0f}. An immediate security deficit exists."
            )

        if inequality_satisfied:
            return (
                f"MOSCA DEFICIT: For {algorithm_name} (migration time X={X:.1f} yrs, data shelf-life Y={Y:.1f} yrs, "
                f"time to CRQC Z={Z:.1f} yrs), the combined timeline X + Y ({X_plus_Y:.1f} yrs) exceeds time to CRQC "
                f"({Z:.1f} yrs). This results in a {delta_M:.1f}-year Mosca deficit where sensitive data remains "
                f"vulnerable to quantum decryption after projected {crqc_year} CRQC arrival (source: {source}), "
                f"yielding a Mosca risk index of {mosca_risk_index:.4f}."
            )

        # Safe buffer
        buffer_years = abs(delta_M)
        return (
            f"SAFE BUFFER: For {algorithm_name} (X={X:.1f} yrs, Y={Y:.1f} yrs, Z={Z:.1f} yrs), "
            f"combined timeline X + Y ({X_plus_Y:.1f} yrs) is within the {Z:.1f}-year quantum horizon. "
            f"A safety buffer of {buffer_years:.1f} years exists before quantum threat arrival under the "
            f"{crqc_year} scenario (source: {source}). Migration must begin by {must_start:.0f}."
        )
