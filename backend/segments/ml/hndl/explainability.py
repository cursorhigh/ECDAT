"""
HNDL Explainability & Rationale Generator (explainability.py)

Generates deterministic, auditable human-readable explanations and policy summaries
strictly derived from the mathematical calculations without altering any scores.
"""

from typing import Dict, Any


class HNDLExplainabilityBuilder:
    """
    Constructs explainability narratives for HNDL risk assessments.
    """

    @classmethod
    def build_explanation(
        cls,
        algorithm_name: str,
        crypto_role: str,
        s_crypto: float,
        s_harvest: float,
        timeline_metrics: Dict[str, Any],
        m_impact: float,
        hndl_score: float,
        applicable: bool,
        assumptions: Dict[str, Any],
        pfs_status: str,
    ) -> str:
        """
        Builds a comprehensive, deterministic explanation narrative.
        """
        lifetime = timeline_metrics.get("data_lifetime_years", 0.0)
        expiry = timeline_metrics.get("data_expiry_year", 2026)
        horizon = assumptions.get("quantum_horizon_year", 2033)
        source = assumptions.get("quantum_horizon_source", "CONFIGURATION")
        window = timeline_metrics.get("exposure_window_years", 0.0)

        if not applicable:
            if s_crypto == 0.0:
                return (
                    f"Algorithm {algorithm_name} is post-quantum secure or non-confidentiality-bearing "
                    f"(cryptographic susceptibility: 0.0). No retrospective decryption threat exists."
                )
            if s_harvest == 0.0:
                return (
                    f"Algorithm {algorithm_name} operates in an isolated, non-interceptable environment "
                    f"(harvestability score: 0.0). No data harvesting vector was identified."
                )
            if window == 0.0:
                return (
                    f"Protected data has a confidentiality lifetime of {lifetime:.1f} years (expiring in {expiry:.0f}). "
                    f"Under the configured {horizon} quantum-horizon scenario (source: {source}), "
                    f"data confidentiality will naturally expire before a cryptanalytically relevant quantum computer (CRQC) arrives. "
                    f"Not exposed under the configured HNDL timeline scenario."
                )
            return (
                f"HNDL is not applicable to {algorithm_name} under the current operational and timeline scenario."
            )

        # Applicable HNDL Explanation
        pfs_text = (
            "Ephemeral Perfect Forward Secrecy (PFS) is absent, allowing retrospective full-session decryption."
            if pfs_status == "LACK_OF_PFS"
            else ("PFS status could not be verified from code evidence." if pfs_status == "UNKNOWN" else "PFS is enforced.")
        )

        explanation = (
            f"Algorithm {algorithm_name} is susceptible to quantum cryptanalysis (susceptibility: {s_crypto:.2f}). "
            f"Protected data has a confidentiality requirement of {lifetime:.1f} years (expiring in {expiry:.0f}). "
            f"Under the configured {horizon} quantum-horizon scenario (source: {source}), "
            f"an exposure window of {window:.1f} years exists where harvested ciphertext can be decrypted while still confidential. "
            f"Interception score is {s_harvest:.2f} ({pfs_text}), yielding a composite HNDL exposure score of {hndl_score:.4f}."
        )

        return explanation
