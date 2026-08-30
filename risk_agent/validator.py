"""
Risk Agent Validator Component

Validates raw input system context and generated Risk Context JSON output structure and fields.
"""

from typing import Dict, Any, Tuple, List, Optional


class RiskAgentValidator:
    """
    Validates inputs and outputs for RiskClassificationAgent.
    """

    ALLOWED_SENSITIVITY = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def validate_input(self, raw_context: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validates raw system context input dictionary.
        """
        errors: List[str] = []
        if not isinstance(raw_context, dict):
            return False, ["Raw context must be a dictionary."]
        if not raw_context:
            errors.append("Raw context dictionary cannot be empty.")
        return len(errors) == 0, errors

    def validate_output(self, risk_context_json: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validates structured Risk Context JSON schema, field types, and value constraints.
        """
        errors: List[str] = []

        if not isinstance(risk_context_json, dict):
            return False, ["Risk context output must be a JSON object (dictionary)."]

        # Validate data_context
        data_ctx = risk_context_json.get("data_context")
        if not isinstance(data_ctx, dict):
            errors.append("Output missing required dictionary field 'data_context'.")
        else:
            sensitivity = str(data_ctx.get("sensitivity") or "").upper()
            if sensitivity not in self.ALLOWED_SENSITIVITY:
                errors.append(
                    f"Invalid data sensitivity '{sensitivity}'. Must be one of {self.ALLOWED_SENSITIVITY}."
                )

            lifetime = data_ctx.get("data_lifetime_years")
            if lifetime is None or not isinstance(lifetime, (int, float)) or lifetime < 0:
                errors.append("Field 'data_context.data_lifetime_years' must be a non-negative integer.")

        # Validate network_context
        net_ctx = risk_context_json.get("network_context")
        if not isinstance(net_ctx, dict):
            errors.append("Output missing required dictionary field 'network_context'.")
        else:
            if "internet_exposed" not in net_ctx or not isinstance(net_ctx["internet_exposed"], bool):
                errors.append("Field 'network_context.internet_exposed' must be a boolean.")

            if "collectable" not in net_ctx or not isinstance(net_ctx["collectable"], bool):
                errors.append("Field 'network_context.collectable' must be a boolean.")

        return len(errors) == 0, errors
