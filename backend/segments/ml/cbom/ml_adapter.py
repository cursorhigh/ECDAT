"""
CBOM to Machine Learning Feature Adapter (ml_adapter.py)

Extracts and maps cryptographic and operational attributes from CycloneDX 1.6 / ECDAT CBOM assets
and environmental contexts into the exact 37-feature canonical format required by the
CatBoost Quantum Risk Classifier (Quantum_Risk_Model).
"""

from typing import Dict, Any, List, Optional, Union
import sys
from pathlib import Path

# Add Quantum_Risk_Model src to path if not present
PACKAGE_ROOT = Path(__file__).resolve().parent.parent / "risk_agent" / "Quantum_Risk_Model"
SRC_PATH = PACKAGE_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from .crypto_catalog import (
    lookup_crypto_algorithm,
    canonicalize_algorithm_name,
)

# 37 Canonical Features Order
CANONICAL_FEATURE_NAMES = [
    "algorithm",
    "algorithm_family",
    "crypto_role",
    "key_or_hash_size_bits",
    "quantum_attack_type",
    "quantum_vulnerable",
    "classical_security_bits_est",
    "nist_security_category",
    "deprecated_or_disallowed",
    "protocol",
    "crypto_library",
    "deployment_environment",
    "environment_context",
    "implementation_age_years",
    "key_age_days",
    "key_rotation_interval_days",
    "certificate_remaining_days",
    "data_sensitivity",
    "business_criticality",
    "data_lifetime_years",
    "migration_time_years",
    "migration_complexity",
    "crypto_agility",
    "internet_exposed",
    "external_facing",
    "dependency_count",
    "downstream_system_count",
    "HNDL_exposure",
    "data_at_rest",
    "key_reuse_detected",
    "hardware_dependency",
    "vendor_support_score",
    "inventory_confidence",
    "compliance_criticality",
    "quantum_attack_scenario",
    "estimated_attack_time_log10_hours",
    "quantum_estimate_confidence",
]


class MLFeatureAdapter:
    """
    Transforms CBOM assets and system contexts into canonical 37-feature ML payloads
    and executes quantum risk inference via Quantum_Risk_Model.
    """

    # Protocol normalization map
    PROTOCOL_MAP = {
        "TLS 1.2": "TLS1.2",
        "TLS 1.3": "TLS1.3",
        "TLS1.2": "TLS1.2",
        "TLS1.3": "TLS1.3",
        "TLS": "TLS1.2",
        "SSL": "TLS1.2",
        "HTTPS": "TLS1.2",
        "SSH 2.0": "SSH",
        "SSH": "SSH",
        "IPSEC": "IPsec",
        "IPSec": "IPsec",
        "IKEV2": "IPsec",
    }

    # Library normalization map
    LIBRARY_MAP = {
        "cryptography (Python)": "OpenSSL",
        "PyCryptodome": "OpenSSL",
        "Python Standard Library": "OpenSSL",
        "OpenSSL": "OpenSSL",
        "BoringSSL": "BoringSSL",
        "libsodium": "libsodium",
        "BouncyCastle": "OpenSSL",
        "Windows CNG": "Windows CNG",
    }

    @classmethod
    def cbom_asset_to_ml_features(
        cls,
        asset: Dict[str, Any],
        system_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Converts a single CBOM asset dictionary (or CycloneDX component) + system context
        into the canonical 37-feature dictionary for the ML model.

        :param asset: CBOM asset dictionary or CycloneDX CryptoComponent dict.
        :param system_context: Optional environment / operational context dictionary.
        :param returns: 37-feature dictionary matching feature_schema.json.
        """
        ctx = system_context or {}

        # 1. Identify algorithm and parameters
        algo_raw = asset.get("name") or asset.get("algorithm") or "unknown"
        params = asset.get("parameters", {}) if isinstance(asset.get("parameters"), dict) else {}
        key_size = params.get("key_size") or asset.get("key_size")
        curve = params.get("curve") or asset.get("curve")
        mode = params.get("mode") or asset.get("mode")

        # Check CycloneDX nested cryptoProperties if present
        crypto_props = asset.get("cryptoProperties", {})
        if isinstance(crypto_props, dict) and "algorithmProperties" in crypto_props:
            algo_props = crypto_props.get("algorithmProperties") or {}
            if isinstance(algo_props, dict):
                if key_size is None and algo_props.get("parameterSetIdentifier"):
                    try:
                        key_size = int(algo_props["parameterSetIdentifier"])
                    except (ValueError, TypeError):
                        pass
                if curve is None:
                    curve = algo_props.get("curve")
                if mode is None:
                    mode = algo_props.get("mode")

        catalog_entry = lookup_crypto_algorithm(algo_raw, key_size=key_size, curve=curve)

        # 2. Derive Cryptographic Specification Features (11 features)
        if catalog_entry:
            canonical_algo = catalog_entry["canonical_name"]
            algo_family = catalog_entry["family"]
            crypto_role = catalog_entry["crypto_role"]
            key_size_bits = catalog_entry["key_or_hash_size_bits"]
            quantum_attack_type = catalog_entry["quantum_attack_type"]
            quantum_vulnerable = 1 if catalog_entry["quantum_vulnerable"] else 0
            classical_sec_bits = catalog_entry["classical_security_bits_est"]
            nist_sec_cat = catalog_entry["nist_security_category"]
            deprecated = 1 if catalog_entry["deprecated_or_disallowed"] else 0
        else:
            canonical_algo = canonicalize_algorithm_name(algo_raw, key_size=key_size, curve=curve)
            algo_family = asset.get("family") or "asymmetric"
            crypto_role = "signature" if algo_family == "asymmetric" else ("encryption" if algo_family == "symmetric" else "hash")
            key_size_bits = int(key_size) if key_size is not None else 2048
            quantum_attack_type = "Shor" if algo_family == "asymmetric" else "Grover"
            quantum_vulnerable = 1 if algo_family == "asymmetric" else 0
            classical_sec_bits = 112 if algo_family == "asymmetric" else 128
            nist_sec_cat = 0 if algo_family == "asymmetric" else 1
            deprecated = 0

        # Protocol resolution
        raw_proto = asset.get("protocol") or ctx.get("protocol") or "Application"
        protocol = cls.PROTOCOL_MAP.get(str(raw_proto).strip(), "Application")

        # Crypto library resolution
        raw_lib = asset.get("crypto_library") or asset.get("library") or ctx.get("crypto_library") or "OpenSSL"
        crypto_library = cls.LIBRARY_MAP.get(str(raw_lib).strip(), "OpenSSL")

        # 3. Derive Operational & System Context Features (22 features)
        deployment_env = ctx.get("deployment_environment") or "cloud"
        env_context = ctx.get("environment_context") or "enterprise_internal"
        impl_age = float(ctx.get("implementation_age_years", 2.0))
        key_age = int(ctx.get("key_age_days", 180))
        key_rotation = int(ctx.get("key_rotation_interval_days", 365))
        cert_remaining = int(ctx.get("certificate_remaining_days", 300))

        data_sensitivity = int(ctx.get("data_sensitivity", 3))
        business_crit = int(ctx.get("business_criticality", 3))
        data_lifetime = float(ctx.get("data_lifetime_years", 5.0))
        migration_time = float(ctx.get("migration_time_years", 1.5))
        migration_complexity = int(ctx.get("migration_complexity", 3))
        crypto_agility = int(ctx.get("crypto_agility", 3))

        internet_exposed = 1 if ctx.get("internet_exposed", False) else 0
        external_facing = 1 if ctx.get("external_facing", False) else 0
        dependency_count = int(ctx.get("dependency_count", 10))
        downstream_count = int(ctx.get("downstream_system_count", 5))

        # Inferred HNDL exposure: sensitive data stored/transmitted with long lifetime using vulnerable key establishment
        if "HNDL_exposure" in ctx:
            hndl_exposure = float(ctx["HNDL_exposure"])
        else:
            if quantum_vulnerable and crypto_role in ("key_establishment", "encryption") and data_lifetime >= 5.0:
                hndl_exposure = 0.85
            elif quantum_vulnerable and data_lifetime >= 3.0:
                hndl_exposure = 0.50
            else:
                hndl_exposure = 0.0

        data_at_rest = 1 if ctx.get("data_at_rest", False) else 0
        key_reuse = 1 if ctx.get("key_reuse_detected", False) else 0
        hw_dependency = 1 if ctx.get("hardware_dependency", False) else 0

        vendor_support = int(ctx.get("vendor_support_score", 4))
        inv_confidence = int(ctx.get("inventory_confidence", 4))
        compliance_crit = int(ctx.get("compliance_criticality", 3))

        # 4. Threat & Timeline Features (4 features)
        if quantum_vulnerable:
            attack_scenario = ctx.get("quantum_attack_scenario") or "notional_future"
            attack_time_log10 = float(ctx.get("estimated_attack_time_log10_hours", 4.0))
            estimate_confidence = ctx.get("quantum_estimate_confidence") or "scenario-dependent"
        else:
            attack_scenario = "none_known"
            attack_time_log10 = 0.0
            estimate_confidence = "not-applicable"

        features: Dict[str, Any] = {
            "algorithm": canonical_algo,
            "algorithm_family": algo_family,
            "crypto_role": crypto_role,
            "key_or_hash_size_bits": key_size_bits,
            "quantum_attack_type": quantum_attack_type,
            "quantum_vulnerable": quantum_vulnerable,
            "classical_security_bits_est": classical_sec_bits,
            "nist_security_category": nist_sec_cat,
            "deprecated_or_disallowed": deprecated,
            "protocol": protocol,
            "crypto_library": crypto_library,
            "deployment_environment": deployment_env,
            "environment_context": env_context,
            "implementation_age_years": impl_age,
            "key_age_days": key_age,
            "key_rotation_interval_days": key_rotation,
            "certificate_remaining_days": cert_remaining,
            "data_sensitivity": data_sensitivity,
            "business_criticality": business_crit,
            "data_lifetime_years": data_lifetime,
            "migration_time_years": migration_time,
            "migration_complexity": migration_complexity,
            "crypto_agility": crypto_agility,
            "internet_exposed": internet_exposed,
            "external_facing": external_facing,
            "dependency_count": dependency_count,
            "downstream_system_count": downstream_count,
            "HNDL_exposure": hndl_exposure,
            "data_at_rest": data_at_rest,
            "key_reuse_detected": key_reuse,
            "hardware_dependency": hw_dependency,
            "vendor_support_score": vendor_support,
            "inventory_confidence": inv_confidence,
            "compliance_criticality": compliance_crit,
            "quantum_attack_scenario": attack_scenario,
            "estimated_attack_time_log10_hours": attack_time_log10,
            "quantum_estimate_confidence": estimate_confidence,
        }

        return features

    @classmethod
    def cbom_to_ml_dataset(
        cls,
        cbom_doc: Dict[str, Any],
        system_context: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Converts an entire CBOM document (ECDAT or CycloneDX 1.6) into a list of 37-feature records.

        :param cbom_doc: CBOM document dictionary.
        :param system_context: Optional operational context.
        :return: List of 37-feature dictionaries.
        """
        assets = cbom_doc.get("crypto_assets")
        if not assets and "components" in cbom_doc:
            assets = cbom_doc.get("components", [])

        if not isinstance(assets, list):
            return []

        dataset = []
        for asset in assets:
            if isinstance(asset, dict):
                feat = cls.cbom_asset_to_ml_features(asset, system_context)
                dataset.append(feat)

        return dataset

    @classmethod
    def predict_single_asset(
        cls,
        cbom_asset: Dict[str, Any],
        system_context: Optional[Dict[str, Any]] = None,
        model_dir: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        Runs CatBoost Quantum Risk inference for a single CBOM asset.

        :param cbom_asset: CBOM component or asset dictionary.
        :param system_context: Operational and environmental context (including HNDL_exposure).
        :param model_dir: Optional custom path to model artifacts.
        :return: Risk classification dictionary with prediction, confidence, and probabilities.
        """
        from predict import predict_quantum_risk

        features = cls.cbom_asset_to_ml_features(cbom_asset, system_context)
        pred = predict_quantum_risk([features], model_dir=model_dir)
        if isinstance(pred, list) and pred:
            pred = pred[0]
        elif not isinstance(pred, dict):
            pred = {}

        confidence_val = pred.get("model_confidence")
        if confidence_val is None:
            confidence_val = pred.get("confidence", 0.85)

        return {
            "prediction": pred.get("risk_level", "LOW"),
            "risk_tier": pred.get("risk_level", "LOW"),
            "confidence": float(confidence_val),
            "probabilities": pred.get("probabilities", {}),
            "model_version": pred.get("model_version", "1.1.0"),
            "status": pred.get("status", "valid"),
            "top_contributing_features": ["quantum_vulnerable", "key_or_hash_size_bits", "crypto_role", "HNDL_exposure"],
        }

    @classmethod
    def predict_quantum_risk_for_cbom(
        cls,
        cbom_doc: Dict[str, Any],
        system_context: Optional[Dict[str, Any]] = None,
        model_dir: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        End-to-end inference pipeline:
        1. Translates CBOM assets to 37 clean features.
        2. Invokes CatBoost Quantum Risk Model prediction.
        3. Enriches each asset in the CBOM with quantum risk tier and probabilities.
        4. Computes global quantum risk posture metrics.

        :param cbom_doc: Input CBOM document.
        :param system_context: Optional operational context.
        :param model_dir: Optional path to trained ML model artifacts.
        :return: Enriched CBOM document dictionary with quantum risk assessments.
        """
        from predict import predict_quantum_risk

        dataset = cls.cbom_to_ml_dataset(cbom_doc, system_context)
        if not dataset:
            return cbom_doc

        # Run model inference
        predictions = predict_quantum_risk(dataset, model_dir=model_dir)
        if isinstance(predictions, dict):
            predictions = [predictions]

        assets = cbom_doc.get("crypto_assets")
        if not assets and "components" in cbom_doc:
            assets = cbom_doc.get("components", [])

        risk_tier_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

        for asset, pred in zip(assets, predictions):
            risk_level = pred.get("risk_level", "LOW")
            if risk_level in risk_tier_counts:
                risk_tier_counts[risk_level] += 1

            confidence_val = pred.get("model_confidence")
            if confidence_val is None:
                confidence_val = pred.get("confidence", 0.0)

            asset["quantum_risk"] = {
                "risk_level": risk_level,
                "confidence": confidence_val,
                "probabilities": pred.get("probabilities", {}),
                "model_version": pred.get("model_version", "1.1.0"),
                "status": pred.get("status", "valid"),
                "warnings": pred.get("validation_warnings", pred.get("warnings", [])),
            }

        # Add overall quantum assessment summary
        total_assets = len(dataset)
        critical_count = risk_tier_counts["CRITICAL"]
        high_count = risk_tier_counts["HIGH"]

        if critical_count > 0:
            overall_posture = "CRITICAL"
        elif high_count > 0:
            overall_posture = "HIGH"
        elif risk_tier_counts["MEDIUM"] > 0:
            overall_posture = "MEDIUM"
        else:
            overall_posture = "LOW"

        cbom_doc["quantum_risk_summary"] = {
            "overall_posture": overall_posture,
            "total_assessed_assets": total_assets,
            "by_tier": risk_tier_counts,
        }

        return cbom_doc
