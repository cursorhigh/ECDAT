"""
Validation Layer for Final Combined Result Module (validator.py)

Validates upstream inputs and synthesized output reports for schema adherence,
attribution completeness, numerical sanity, and cryptographic correctness.
"""

from typing import Dict, Any, Tuple, List
import logging
from .models import AssetInputBundle, AssetSynthesisReport, FinalExecutiveReport

logger = logging.getLogger(__name__)


class SynthesisValidator:
    """Validator for inputs and outputs in the final report synthesis pipeline."""

    @classmethod
    def validate_asset_bundle(cls, bundle: Dict[str, Any]) -> Tuple[bool, List[str]]:
        errors: List[str] = []
        if not isinstance(bundle, dict):
            return False, ["Asset bundle must be a dictionary"]

        asset_id = bundle.get("asset_id") or bundle.get("id")
        if not asset_id:
            errors.append("Missing required field 'asset_id'")

        algo = bundle.get("algorithm") or bundle.get("name")
        if not algo:
            errors.append("Missing required field 'algorithm'")

        return len(errors) == 0, errors

    @classmethod
    def validate_asset_synthesis_report(cls, report: Dict[str, Any]) -> Tuple[bool, List[str]]:
        errors: List[str] = []
        try:
            AssetSynthesisReport(**report)
        except Exception as e:
            errors.append(f"Asset synthesis report schema validation failed: {e}")

        # Check required fields
        if "overall_quantum_risk_tier" not in report:
            errors.append("Missing 'overall_quantum_risk_tier'")
        if "unified_risk_score" not in report:
            errors.append("Missing 'unified_risk_score'")
        if "attributions" not in report or not isinstance(report.get("attributions"), list):
            errors.append("Missing or invalid 'attributions' list")

        # 1. PQC Status & Recommendation rules
        algo = str(report.get("algorithm", "")).upper()
        pqc = str(report.get("pqc_status", "")).upper()
        rec = str(report.get("recommended_action", ""))

        if pqc == "PQC_NATIVE":
            if "replace" in rec.lower() and "fips 203" in rec.lower():
                errors.append(f"PQC_NATIVE asset {algo} must not be told to replace itself with FIPS 203.")
            if "203/204/205" in rec:
                errors.append("Generic grouped FIPS 203/204/205 standard recommendation used for specific algorithm.")

        if "ML-KEM" in algo and "204" in rec:
            errors.append("ML-KEM incorrectly mapped to FIPS 204 (should be FIPS 203).")
        if "ML-DSA" in algo and "203" in rec:
            errors.append("ML-DSA incorrectly mapped to FIPS 203 (should be FIPS 204).")

        # 2. Unified Numerical Score in [0, 100]
        score = report.get("unified_risk_score")
        if score is not None:
            try:
                score_num = float(score)
                if not (0.0 <= score_num <= 100.0):
                    errors.append(f"Unified risk score {score_num} is outside [0.0, 100.0].")
            except (ValueError, TypeError):
                errors.append(f"Invalid numerical unified risk score: {score}")

        # 3. Policy overrides must have reasons
        overrides = report.get("policy_overrides", [])
        if overrides and not isinstance(overrides, list):
            errors.append("policy_overrides must be a list of reason strings.")

        return len(errors) == 0, errors

    @classmethod
    def validate_final_report(cls, report: Dict[str, Any]) -> Tuple[bool, List[str]]:
        errors: List[str] = []
        try:
            FinalExecutiveReport(**report)
        except Exception as e:
            errors.append(f"Final executive report schema validation failed: {e}")

        stats = report.get("portfolio_stats", {})
        exec_summary = str(report.get("executive_summary", ""))

        # 4. Check for 'deadline of None' text
        if "deadline of None" in exec_summary or "deadline of None" in str(report.get("key_findings", [])):
            errors.append("Narrative contains invalid literal 'deadline of None'.")

        # 5. Check earliest deadline consistency
        earliest_dl = stats.get("earliest_migration_deadline_year")
        if earliest_dl is not None:
            try:
                float(earliest_dl)
            except (ValueError, TypeError):
                errors.append(f"Invalid earliest_migration_deadline_year format: {earliest_dl}")

        return len(errors) == 0, errors
