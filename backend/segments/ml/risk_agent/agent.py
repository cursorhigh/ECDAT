"""
Risk Classification Agent (agent.py)

Orchestrates quantum risk classification using the 37-feature CatBoost Quantum Risk Model
and the CBOM ML Feature Adapter.
"""

from typing import Dict, Any, List, Optional, Union
from segments.ml.cbom.ml_adapter import MLFeatureAdapter


class RiskClassificationAgent:
    """
    Agent responsible for analyzing organizational system contexts, assessing CBOM
    cryptographic assets, and classifying quantum risk tiers using the CatBoost model.
    """

    def __init__(self, model_dir: Optional[str] = None):
        self.model_dir = model_dir
        self.adapter = MLFeatureAdapter()

    def analyze(self, raw_system_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Analyzes and canonicalizes raw system operational context (e.g. cloud, data lifetime, business criticality).

        :param raw_system_context: Dictionary of operational attributes.
        :return: Clean canonical system risk context dictionary.
        """
        ctx = raw_system_context or {}
        
        return {
            "deployment_environment": ctx.get("deployment_environment") or "cloud",
            "environment_context": ctx.get("environment_context") or "enterprise_internal",
            "implementation_age_years": float(ctx.get("implementation_age_years", 2.0)),
            "key_age_days": int(ctx.get("key_age_days", 180)),
            "key_rotation_interval_days": int(ctx.get("key_rotation_interval_days", 365)),
            "certificate_remaining_days": int(ctx.get("certificate_remaining_days", 300)),
            "data_sensitivity": int(ctx.get("data_sensitivity", 3)),
            "business_criticality": int(ctx.get("business_criticality", 3)),
            "data_lifetime_years": float(ctx.get("data_lifetime_years", 5.0)),
            "migration_time_years": float(ctx.get("migration_time_years", 1.5)),
            "migration_complexity": int(ctx.get("migration_complexity", 3)),
            "crypto_agility": int(ctx.get("crypto_agility", 3)),
            "internet_exposed": bool(ctx.get("internet_exposed", False)),
            "external_facing": bool(ctx.get("external_facing", False)),
            "dependency_count": int(ctx.get("dependency_count", 10)),
            "downstream_system_count": int(ctx.get("downstream_system_count", 5)),
            "HNDL_exposure": float(ctx.get("HNDL_exposure", 0.5)),
            "data_at_rest": bool(ctx.get("data_at_rest", False)),
            "key_reuse_detected": bool(ctx.get("key_reuse_detected", False)),
            "hardware_dependency": bool(ctx.get("hardware_dependency", False)),
            "vendor_support_score": int(ctx.get("vendor_support_score", 4)),
            "inventory_confidence": int(ctx.get("inventory_confidence", 4)),
            "compliance_criticality": int(ctx.get("compliance_criticality", 3)),
        }

    def assess_asset_risk(
        self,
        asset: Dict[str, Any],
        system_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Assesses a single CBOM asset against the 37-feature CatBoost model.

        :param asset: Single CBOM asset dictionary.
        :param system_context: Operational system context.
        :return: Risk classification dictionary with risk_level, confidence, and probabilities.
        """
        from predict import predict_quantum_risk

        features = self.adapter.cbom_asset_to_ml_features(asset, system_context)
        pred = predict_quantum_risk(features, model_dir=self.model_dir)
        if isinstance(pred, list) and pred:
            pred = pred[0]

        return pred

    def assess_cbom(
        self,
        cbom_doc: Dict[str, Any],
        system_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Assesses all assets in a CBOM document and attaches quantum risk metrics.

        :param cbom_doc: Validated CBOM document.
        :param system_context: Operational system context.
        :return: Enriched CBOM document.
        """
        return self.adapter.predict_quantum_risk_for_cbom(
            cbom_doc=cbom_doc,
            system_context=system_context,
            model_dir=self.model_dir,
        )
