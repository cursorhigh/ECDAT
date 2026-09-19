"""
MOSCA+ Output & Input Validator

Validates structural completeness and field value constraints for CBOM inputs
and generated MOSCA+ assessment JSON outputs.
"""

from typing import Dict, Any, Tuple, List, Optional


class MOSCAValidator:
    """
    Validates inputs and outputs for MOSCA+ Agent.
    """

    ALLOWED_CLASSICAL_SECURITY = {"LOW", "MEDIUM", "HIGH", "UNKNOWN"}
    ALLOWED_QUANTUM_RISK = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}
    ALLOWED_OVERALL_RISK = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}
    ALLOWED_MIGRATION_PRIORITY = {"LOW", "MEDIUM", "HIGH", "URGENT", "UNKNOWN"}

    def validate_input(self, cbom_asset: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validates input CBOM asset structure.
        """
        errors: List[str] = []
        if not isinstance(cbom_asset, dict):
            return False, ["CBOM asset must be a dictionary."]

        asset_id = cbom_asset.get("asset_id")
        if not asset_id or not isinstance(asset_id, str):
            errors.append("CBOM asset missing required string field 'asset_id'.")

        algo = cbom_asset.get("algorithm")
        if not algo:
            errors.append("CBOM asset missing required field 'algorithm'.")

        return len(errors) == 0, errors

    def validate(
        self, result: Dict[str, Any], expected_asset_id: Optional[str] = None
    ) -> Tuple[bool, List[str]]:
        """
        Validates generated MOSCA+ assessment JSON schema and field constraints.

        :param result: Generated MOSCA+ result dictionary.
        :param expected_asset_id: Expected CBOM asset_id to enforce exact match.
        :return: Tuple (is_valid: bool, list_of_error_messages)
        """
        errors: List[str] = []

        if not isinstance(result, dict):
            return False, ["MOSCA output must be a dictionary."]

        asset_id = result.get("asset_id")
        if not asset_id:
            errors.append("MOSCA output missing required field 'asset_id'.")
        elif expected_asset_id and asset_id != expected_asset_id:
            errors.append(
                f"MOSCA output asset_id '{asset_id}' does not match input asset_id '{expected_asset_id}'."
            )

        assessment = result.get("mosca_assessment")
        if not isinstance(assessment, dict):
            errors.append("MOSCA output missing required dictionary field 'mosca_assessment'.")
            return False, errors

        # Field: algorithm_category
        if not assessment.get("algorithm_category") or not isinstance(assessment["algorithm_category"], str):
            errors.append("Field 'mosca_assessment.algorithm_category' must be a non-empty string.")

        # Field: classical_security
        cs = str(assessment.get("classical_security") or "").upper()
        if cs not in self.ALLOWED_CLASSICAL_SECURITY:
            errors.append(
                f"Field 'mosca_assessment.classical_security' must be one of {self.ALLOWED_CLASSICAL_SECURITY}. Got '{cs}'."
            )

        # Field: quantum_vulnerable
        qv = assessment.get("quantum_vulnerable")
        if qv is not None and not isinstance(qv, bool):
            errors.append("Field 'mosca_assessment.quantum_vulnerable' must be boolean or null.")

        # Field: quantum_migration_risk
        qmr = str(assessment.get("quantum_migration_risk") or "").upper()
        if qmr not in self.ALLOWED_QUANTUM_RISK:
            errors.append(
                f"Field 'mosca_assessment.quantum_migration_risk' must be one of {self.ALLOWED_QUANTUM_RISK}. Got '{qmr}'."
            )

        # Field: overall_risk
        overall = str(assessment.get("overall_risk") or "").upper()
        if overall not in self.ALLOWED_OVERALL_RISK:
            errors.append(
                f"Field 'mosca_assessment.overall_risk' must be one of {self.ALLOWED_OVERALL_RISK}. Got '{overall}'."
            )

        # Field: migration_priority
        mp = str(assessment.get("migration_priority") or "").upper()
        if mp not in self.ALLOWED_MIGRATION_PRIORITY:
            errors.append(
                f"Field 'mosca_assessment.migration_priority' must be one of {self.ALLOWED_MIGRATION_PRIORITY}. Got '{mp}'."
            )

        # Field: recommended_action
        action = assessment.get("recommended_action")
        if not action or not isinstance(action, str) or not action.strip():
            errors.append("Field 'mosca_assessment.recommended_action' must be a non-empty string.")

        # Field: reason
        reason = assessment.get("reason")
        if not reason or not isinstance(reason, str) or not reason.strip():
            errors.append("Field 'mosca_assessment.reason' must be a non-empty string.")

        return len(errors) == 0, errors
