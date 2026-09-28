"""
Gemini and Fallback Providers for Report Synthesis (gemini_provider.py)

Manages Google Gemini API communication for final report generation and provides
a deterministic, auditable fallback synthesis engine.
Strictly separates ML predictions, confidence, PQC classification, policy overrides,
and unified risk scoring.
"""

import os
import json
import re
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Union

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from segments.ml.cbom.crypto_catalog import classify_pqc_status, lookup_crypto_algorithm
from .models import AssetSynthesisReport, FinalExecutiveReport, AttributionEvidence, PortfolioSummaryStats
from .prompts import (
    FINAL_REPORT_SYNTHESIS_SYSTEM_PROMPT,
    ASSET_SYNTHESIS_USER_PROMPT_TEMPLATE,
    PORTFOLIO_SYNTHESIS_USER_PROMPT_TEMPLATE,
)

logger = logging.getLogger(__name__)


def clean_llm_json(raw_text: str) -> Dict[str, Any]:
    """
    Strips markdown formatting and parses clean JSON from an LLM response.
    """
    if not raw_text or not isinstance(raw_text, str):
        return {}
    cleaned = raw_text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE).strip()
    cleaned = re.sub(r"\s*```$", "", cleaned).strip()
    try:
        return json.loads(cleaned)
    except Exception as e:
        logger.warning("Failed to parse JSON from LLM response: %s", e)
        match = re.search(r"(\{.*\})", cleaned, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except Exception:
                pass
        return {}


class BaseReportProvider(ABC):
    """Abstract interface for report synthesis providers."""

    @abstractmethod
    def synthesize_asset_report(
        self,
        asset_bundle: Dict[str, Any],
        ml_summary: Dict[str, Any],
        hndl_summary: Dict[str, Any],
        mosca_summary: Dict[str, Any],
    ) -> Dict[str, Any]:
        pass

    @abstractmethod
    def synthesize_portfolio_report(
        self,
        portfolio_stats: Dict[str, Any],
        asset_summaries: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        pass


class DeterministicFallbackProvider(BaseReportProvider):
    """
    Deterministic rule-based report synthesizer that generates high-fidelity,
    transparent, explainable narratives, scores, and source attributions.
    """

    def synthesize_asset_report(
        self,
        asset_bundle: Dict[str, Any],
        ml_summary: Dict[str, Any],
        hndl_summary: Dict[str, Any],
        mosca_summary: Dict[str, Any],
    ) -> Dict[str, Any]:
        asset_id = asset_bundle.get("asset_id", "UNKNOWN")
        algo = asset_bundle.get("algorithm", "UNKNOWN")
        params = asset_bundle.get("parameters", {})
        role = str(asset_bundle.get("crypto_role") or asset_bundle.get("purpose") or "").lower()

        # 1. Classify PQC & Cryptographic Status
        catalog_entry = lookup_crypto_algorithm(algo, key_size=params.get("key_size"), curve=params.get("curve"))
        pqc_status = classify_pqc_status(algo, catalog_entry=catalog_entry, parameters=params)

        # 2. Extract Pillar Metrics
        ml_pred = str(ml_summary.get("risk_tier") or ml_summary.get("prediction") or "LOW").upper()
        ml_conf_raw = float(ml_summary.get("confidence", 0.85))
        ml_conf_pct = round(ml_conf_raw * 100.0 if ml_conf_raw <= 1.0 else ml_conf_raw, 1)
        top_features = ml_summary.get("top_contributing_features", [])

        hndl_exposure = float(hndl_summary.get("hndl_exposure_score", 0.0))
        hndl_harvest = float(hndl_summary.get("harvestability_score", 0.0))
        hndl_risk_tier = str(hndl_summary.get("future_decryption_risk", "NEGLIGIBLE")).upper()
        is_hndl_exposed = bool(
            pqc_status in ("CLASSICAL_VULNERABLE", "LEGACY_DEPRECATED")
            and hndl_exposure >= 0.15
            and hndl_risk_tier in ("CRITICAL", "HIGH", "MEDIUM")
        )

        mosca_deficit = float(mosca_summary.get("deficit_years", 0.0)) if mosca_summary.get("deficit_years") is not None else 0.0
        mosca_satisfied = bool(mosca_summary.get("inequality_satisfied", False))
        mosca_urgency = str(mosca_summary.get("urgency_tier", "LOW")).upper()
        mosca_posture = str(mosca_summary.get("migration_posture", "SAFE_BUFFER")).upper()
        must_start_val = mosca_summary.get("must_start_by_year")
        is_overdue = bool(mosca_summary.get("is_overdue_to_start", False))

        is_mosca_threat = bool(
            pqc_status in ("CLASSICAL_VULNERABLE", "LEGACY_DEPRECATED")
            and mosca_satisfied
            and mosca_urgency in ("CRITICAL", "HIGH", "MEDIUM")
            and mosca_posture != "QUANTUM_RESILIENT"
        )

        # 3. Derive Migration Requirement & Deadline
        if pqc_status in ("PQC_NATIVE", "HYBRID_PQC"):
            migration_required = False
            migration_deadline = None
        elif pqc_status in ("SYMMETRIC_QUANTUM_RESILIENT", "SYMMETRIC_TRANSITIONAL"):
            migration_required = False
            migration_deadline = None
        else:  # CLASSICAL_VULNERABLE or LEGACY_DEPRECATED
            migration_required = True
            migration_deadline = must_start_val if must_start_val is not None else None

        # 4. Compute Transparent Unified Numerical Score (0.0 to 100.0)
        risk_drivers: List[str] = []

        if pqc_status == "PQC_NATIVE":
            unified_score = 0.0
            risk_drivers.append("PQC_NATIVE_ALGORITHM")
        elif pqc_status == "HYBRID_PQC":
            unified_score = 5.0
            risk_drivers.append("HYBRID_PQC_DEPLOYED")
        elif pqc_status == "SYMMETRIC_QUANTUM_RESILIENT":
            unified_score = 5.0
            risk_drivers.append("SYMMETRIC_QUANTUM_RESILIENT_256BIT")
        elif pqc_status == "SYMMETRIC_TRANSITIONAL":
            unified_score = 12.0
            risk_drivers.append("SYMMETRIC_128BIT_TRANSITIONAL")
        elif pqc_status == "LEGACY_DEPRECATED":
            unified_score = 20.0
            risk_drivers.append("DEPRECATED_PRIMITIVE")
        else:  # CLASSICAL_VULNERABLE
            # Multi-variable weighted sum
            ml_weight_map = {"CRITICAL": 35.0, "HIGH": 25.0, "MEDIUM": 15.0, "LOW": 5.0}
            ml_pts = ml_weight_map.get(ml_pred, 15.0)

            hndl_pts = hndl_exposure * 35.0  # up to 35 pts
            mosca_pts = (30.0 if mosca_deficit >= 5.0 else (20.0 if mosca_deficit >= 2.0 else (10.0 if mosca_deficit > 0 else 0.0)))

            unified_score = round(min(100.0, max(0.0, ml_pts + hndl_pts + mosca_pts)), 1)

            if ml_pred in ("CRITICAL", "HIGH"):
                risk_drivers.append(f"ML_PREDICTION_{ml_pred}")
            if is_hndl_exposed:
                risk_drivers.append("HNDL_EXPOSURE_THREAT")
            if is_mosca_threat:
                risk_drivers.append(f"MOSCA_DEFICIT_{mosca_deficit:+.1f}Y")

        # 5. Determine Base Risk Class from Numerical Score
        # Thresholds: 0-9.99 = LOW, 10-24.99 = MEDIUM, 25-49.99 = HIGH, 50-100 = CRITICAL
        if unified_score >= 50.0:
            base_risk_class = "CRITICAL"
        elif unified_score >= 25.0:
            base_risk_class = "HIGH"
        elif unified_score >= 10.0:
            base_risk_class = "MEDIUM"
        else:
            base_risk_class = "LOW"

        # 6. Apply Explicit Policy Overrides
        policy_overrides: List[str] = []
        policy_status = "COMPLIANT"

        if pqc_status == "LEGACY_DEPRECATED":
            policy_status = "DEPRECATED_ALGORITHM"
            final_risk_class = "HIGH"
            policy_overrides.append(f"POLICY_OVERRIDE: {algo} is deprecated by NIST SP 800-131A (disallowed after 2023)")
            risk_drivers.append("POLICY_DEPRECATED_OVERRIDE")
        elif pqc_status == "HYBRID_PQC" or pqc_status == "PQC_NATIVE":
            policy_status = "PQC_DEPLOYED"
            final_risk_class = "LOW"
        elif pqc_status == "SYMMETRIC_QUANTUM_RESILIENT":
            policy_status = "COMPLIANT"
            final_risk_class = "LOW"
        else:
            final_risk_class = base_risk_class
            policy_status = "CLASSICAL_VULNERABLE"

        # Urgency Tier
        if final_risk_class == "CRITICAL" or is_overdue:
            urgency_tier = "IMMEDIATE" if is_overdue else "CRITICAL"
        elif final_risk_class == "HIGH":
            urgency_tier = "HIGH"
        elif final_risk_class == "MEDIUM":
            urgency_tier = "MEDIUM"
        else:
            urgency_tier = "LOW" if unified_score > 0 else "NEGLIGIBLE"

        # 7. Determine Primary Risk Driver
        if policy_overrides:
            primary_driver = f"Cryptographic Policy Override: {algo} is deprecated and disallowed"
        elif is_overdue:
            primary_driver = "Overdue Mosca Migration Start Deadline"
        elif is_mosca_threat and mosca_deficit > 0:
            primary_driver = f"Mosca Theorem Timeline Deficit (+{mosca_deficit:.1f}y) & Long-Lived Shelf Life"
        elif is_hndl_exposed:
            primary_driver = f"Harvest-Now-Decrypt-Later Threat (Exposure Score: {hndl_exposure:.2f})"
        elif pqc_status == "CLASSICAL_VULNERABLE":
            primary_driver = f"Quantum-Vulnerable Classical Asymmetric Primitive ({algo})"
        elif pqc_status == "HYBRID_PQC":
            primary_driver = "Hybrid Post-Quantum Key Establishment Deployed"
        elif pqc_status == "PQC_NATIVE":
            if "KEM" in algo.upper():
                primary_driver = f"Native Post-Quantum Key Encapsulation (NIST FIPS 203 {algo})"
            elif "DSA" in algo.upper() or "DILITHIUM" in algo.upper():
                primary_driver = f"Native Post-Quantum Digital Signature (NIST FIPS 204 {algo})"
            elif "SLH" in algo.upper() or "SPHINCS" in algo.upper():
                primary_driver = f"Native Post-Quantum Stateless Hash-Based Signature (NIST FIPS 205 {algo})"
            else:
                primary_driver = f"Native Post-Quantum Cryptography ({algo})"
        else:
            primary_driver = "Quantum-Resilient Baseline Cryptography"

        # 8. Purpose-Aware, Algorithm-Tailored Recommendations
        algo_upper = algo.upper()
        role_lower = role.lower()
        is_key_exchange_role = any(r in role_lower for r in ["key", "exch", "enc", "kdf", "kem", "trans", "tls"]) and not any(r in role_lower for r in ["sign", "sig", "code_sign"])
        is_signing_role = any(r in role_lower for r in ["sign", "sig", "code_sign"]) and not any(r in role_lower for r in ["exch", "kdf", "kem"])

        if pqc_status == "PQC_NATIVE":
            if "KEM" in algo_upper:
                rec_action = f"Maintain NIST FIPS 203 {algo} deployment; validate implementation correctness, side-channel protections, and crypto-agility."
            elif "DSA" in algo_upper:
                rec_action = f"Maintain NIST FIPS 204 {algo} deployment; validate implementation correctness, side-channel protections, and crypto-agility."
            elif "SLH" in algo_upper:
                rec_action = f"Maintain NIST FIPS 205 {algo} deployment; validate implementation correctness, side-channel protections, and crypto-agility."
            else:
                rec_action = f"Maintain {algo} post-quantum deployment; validate implementation correctness and crypto-agility."
        elif pqc_status == "HYBRID_PQC":
            rec_action = f"Maintain {algo} hybrid deployment; validate decapsulation downgrade resistance, implementation correctness, and ensure crypto-agility."
        elif "3DES" in algo_upper or "DES" in algo_upper or "RC4" in algo_upper:
            rec_action = f"Retire legacy {algo} immediately per NIST SP 800-131A; migrate to modern symmetric AEAD (AES-256-GCM)."
        elif "AES-128" in algo_upper:
            rec_action = "Assess data retention and security requirements; consider transitioning to AES-256-GCM for long-lived sensitive data (>10 years)."
        elif "AES" in algo_upper or "CHACHA" in algo_upper:
            rec_action = "Maintain AES-256 with authenticated Galois/Counter Mode (GCM); ensure unique nonces and enforce cryptographic agility."
        elif any(k in algo_upper for k in ["DH", "ECDH", "X25519", "X448"]):
            rec_action = f"Migrate key establishment from {algo} to NIST FIPS 203 ML-KEM-768 (or hybrid X25519+ML-KEM-768); enforce Perfect Forward Secrecy."
        elif any(s in algo_upper for s in ["ECDSA", "ED25519", "DSA"]):
            rec_action = f"Migrate digital signatures from {algo} to NIST FIPS 204 ML-DSA-65 or NIST FIPS 205 SLH-DSA."
        elif "RSA" in algo_upper:
            if is_key_exchange_role:
                rec_action = f"Migrate key establishment from {algo} to NIST FIPS 203 ML-KEM-768 (or hybrid X25519+ML-KEM-768); enforce Perfect Forward Secrecy."
            elif is_signing_role:
                rec_action = f"Migrate digital signatures from {algo} to NIST FIPS 204 ML-DSA-65 or NIST FIPS 205 SLH-DSA."
            else:
                # Ambiguous role (e.g. 'authentication', 'token', 'session', 'general', or unspecified)
                rec_action = f"{algo} is quantum-vulnerable. Determine whether the {algo} usage provides key establishment, encryption, or digital signatures, then migrate to the corresponding NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), or FIPS 205 (SLH-DSA) mechanism."
        else:
            rec_action = f"Evaluate cryptographic agility and replace vulnerable {algo} with approved post-quantum algorithms."

        # 9. Build Explicit Source Attributions
        attributions: List[AttributionEvidence] = [
            AttributionEvidence(
                pillar="ML_RISK",
                metric_name="prediction_confidence",
                value=f"{ml_pred} ({ml_conf_pct}%)",
                source_detail=f"CatBoost 37-feature model classified asset as {ml_pred} with {ml_conf_pct}% probability based on features {top_features[:3]}",
            ),
            AttributionEvidence(
                pillar="CBOM_CATALOG",
                metric_name="pqc_status",
                value=pqc_status,
                source_detail=f"NIST SP 800-57 / FIPS 203-205 reference catalog mapped algorithm to {pqc_status}",
            ),
        ]

        if is_hndl_exposed or pqc_status == "CLASSICAL_VULNERABLE":
            attributions.append(
                AttributionEvidence(
                    pillar="HNDL_ENGINE",
                    metric_name="hndl_exposure_score",
                    value=hndl_exposure,
                    source_detail=f"HNDL Engine evaluated harvestability {hndl_harvest:.2f} and decryption risk tier as {hndl_risk_tier}",
                )
            )

        if pqc_status in ("CLASSICAL_VULNERABLE", "LEGACY_DEPRECATED"):
            if mosca_deficit > 0:
                mosca_detail = f"Mosca Inequality X+Y>Z computed timeline deficit +{mosca_deficit:.1f}y (Must start by: {must_start_val})"
            elif mosca_deficit < 0:
                mosca_detail = f"Mosca Inequality X+Y<=Z computed timeline margin {abs(mosca_deficit):.1f}y (ΔM = {mosca_deficit:+.1f}y, Must start by: {must_start_val})"
            else:
                mosca_detail = f"Mosca Inequality X+Y=Z at boundary margin 0.0y (Must start by: {must_start_val})"

            attributions.append(
                AttributionEvidence(
                    pillar="MOSCA_THEOREM",
                    metric_name="mosca_deficit_years",
                    value=mosca_deficit if mosca_deficit else 0.0,
                    source_detail=mosca_detail,
                )
            )

        if policy_overrides:
            attributions.append(
                AttributionEvidence(
                    pillar="POLICY_ENGINE",
                    metric_name="policy_override",
                    value=policy_overrides[0],
                    source_detail="Policy compliance rule triggered risk reclassification",
                )
            )

        # 10. Build Executive Narrative
        deadline_str = f"Must start migration by {migration_deadline}" if migration_deadline else "No immediate post-quantum migration deadline required"
        narrative = (
            f"Asset '{asset_id}' utilizing {algo} is classified as {pqc_status} with an overall {final_risk_class} risk (Score: {unified_score}/100, Urgency: {urgency_tier}). "
            f"[ML Risk Model] predicted class '{ml_pred}' with {ml_conf_pct}% confidence. "
        )
        if policy_overrides:
            narrative += f"[Policy Engine] applied an override: {policy_overrides[0]}. "
        if pqc_status in ("CLASSICAL_VULNERABLE", "LEGACY_DEPRECATED"):
            if mosca_deficit > 0:
                mosca_narrative = f"[Mosca Theorem] calculated timeline deficit +{mosca_deficit:.1f} years ({deadline_str})."
            elif mosca_deficit < 0:
                mosca_narrative = f"[Mosca Theorem] calculated timeline margin of {abs(mosca_deficit):.1f} years (ΔM = {mosca_deficit:.1f}y, {deadline_str})."
            else:
                mosca_narrative = f"[Mosca Theorem] evaluated timeline at exact boundary (ΔM = 0.0y, {deadline_str})."

            narrative += (
                f"[HNDL Engine] evaluated exposure score at {hndl_exposure:.2f} ({hndl_risk_tier}). "
                f"{mosca_narrative}"
            )
        else:
            narrative += "[PQC / Resilient Baseline] algorithm is quantum safe against Shor's algorithm; migration is not required."

        return {
            "asset_id": asset_id,
            "algorithm": algo,
            "pqc_status": pqc_status,
            "policy_status": policy_status,
            "policy_overrides": policy_overrides,
            "base_risk_class": base_risk_class,
            "final_risk_class": final_risk_class,
            "overall_quantum_risk_tier": final_risk_class,
            "unified_risk_score": unified_score,
            "migration_required": migration_required,
            "migration_deadline": migration_deadline,
            "urgency_tier": urgency_tier,
            "ml_prediction": ml_pred,
            "ml_confidence_pct": ml_conf_pct,
            "risk_drivers": risk_drivers,
            "primary_risk_driver": primary_driver,
            "executive_narrative": narrative,
            "attributions": [attr.model_dump() for attr in attributions],
            "recommended_action": rec_action,
        }

    def synthesize_portfolio_report(
        self,
        portfolio_stats: Dict[str, Any],
        asset_summaries: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        total = portfolio_stats.get("total_assets", len(asset_summaries))
        critical = portfolio_stats.get("critical_risk_count", 0)
        high = portfolio_stats.get("high_risk_count", 0)
        medium = portfolio_stats.get("medium_risk_count", 0)
        low = portfolio_stats.get("low_risk_count", 0)
        hndl = portfolio_stats.get("hndl_exposed_count", 0)
        mosca = portfolio_stats.get("mosca_deficit_count", 0)
        overdue = portfolio_stats.get("overdue_migration_count", 0)
        deadline = portfolio_stats.get("earliest_migration_deadline_year")

        deadline_text = f"Earliest mandatory migration start deadline is {deadline}." if deadline is not None else "Migration timeline deadlines are not applicable or not established due to resilient primitives."

        executive_summary = (
            f"Executive Post-Quantum Cryptographic Assessment completed across {total} identified assets. "
            f"The application inventory contains {critical} CRITICAL, {high} HIGH, {medium} MEDIUM, and {low} LOW risk components. "
            f"Analysis indicates {mosca} classical assets are in active timeline deficit under Michele Mosca's Theorem (X + Y > Z), "
            f"with {overdue} assets currently overdue for migration start. "
            f"{hndl} assets present active Harvest-Now-Decrypt-Later exposure. "
            f"{deadline_text}"
        )

        key_findings = [
            f"{critical + high} of {total} assets ({((critical+high)/max(1, total))*100:.1f}%) require prioritized remediation or post-quantum migration [ML Risk & Policy].",
            f"{hndl} assets exhibit interceptability risks requiring Perfect Forward Secrecy or PQC encapsulation [HNDL Engine].",
            f"{deadline_text} [Mosca Theorem].",
        ]

        source_attribution_summary = {
            "ML_RISK": "CatBoost 37-feature classifier evaluated multi-variable cryptographic feature vectors and class probabilities.",
            "HNDL_ENGINE": "Evaluated adversary interceptability and data confidentiality shelf-life against the CRQC horizon.",
            "MOSCA_THEOREM": "Calculated mathematical migration time (X), data shelf-life (Y), and CRQC horizon (Z) deficits.",
            "POLICY_ENGINE": "Enforced NIST SP 800-131A legacy algorithm deprecation and FIPS 203-205 compliance standards.",
        }

        return {
            "report_title": "ECDAT Enterprise Post-Quantum Cryptographic Risk Report",
            "executive_summary": executive_summary,
            "key_findings": key_findings,
            "source_attribution_summary": source_attribution_summary,
        }


class GeminiReportProvider(BaseReportProvider):
    """
    Google Gemini AI Report Synthesizer with automatic fallback to DeterministicFallbackProvider.
    """

    DEFAULT_MODELS = [
        "gemini-3.5-flash-lite",
        "gemini-3.1-flash-lite",
        "gemini-3.6-flash",
    ]

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = (
            api_key
            or os.getenv("GEMINI_API_KEY_FINAL")
            or os.getenv("GEMINI_API_KEY_SYNTHESIS")
            or os.getenv("GEMINI_API_KEY_MOSCA")
            or os.getenv("GEMINI_API_KEY")
        )
        user_model = model or os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
        candidate_list = [user_model] + [m for m in self.DEFAULT_MODELS if m != user_model]
        self.candidate_models: List[str] = []
        for m in candidate_list:
            if m not in self.candidate_models:
                self.candidate_models.append(m)
        self.model = self.candidate_models[0]
        self.fallback = DeterministicFallbackProvider()

    def synthesize_asset_report(
        self,
        asset_bundle: Dict[str, Any],
        ml_summary: Dict[str, Any],
        hndl_summary: Dict[str, Any],
        mosca_summary: Dict[str, Any],
    ) -> Dict[str, Any]:
        # Always run fallback to get deterministic baseline & policy overrides
        deterministic_base = self.fallback.synthesize_asset_report(
            asset_bundle, ml_summary, hndl_summary, mosca_summary
        )

        if not self.api_key:
            return deterministic_base

        asset_id = asset_bundle.get("asset_id", "UNKNOWN")
        algo = asset_bundle.get("algorithm", "UNKNOWN")
        family = asset_bundle.get("family", "")
        role = asset_bundle.get("crypto_role", "")
        params = asset_bundle.get("parameters", {})
        ctx = asset_bundle.get("operational_context", {})

        prompt = ASSET_SYNTHESIS_USER_PROMPT_TEMPLATE.format(
            asset_id=asset_id,
            algorithm=algo,
            family=family,
            crypto_role=role,
            parameters=json.dumps(params),
            ml_risk_json=json.dumps(ml_summary, indent=2),
            hndl_json=json.dumps(hndl_summary, indent=2),
            mosca_json=json.dumps(mosca_summary, indent=2),
            operational_context_json=json.dumps(ctx, indent=2),
        )

        try:
            raw_text = self._call_gemini(prompt)
            parsed = clean_llm_json(raw_text)
            if parsed and "executive_narrative" in parsed:
                # Merge AI narrative while strictly preserving deterministic risk classifications and policy overrides
                deterministic_base["executive_narrative"] = parsed["executive_narrative"]
                if "recommended_action" in parsed and parsed["recommended_action"]:
                    # Ensure Gemini does not recommend replacing FIPS 203 with FIPS 203
                    if not (deterministic_base["pqc_status"] == "PQC_NATIVE" and "REPLACE" in parsed["recommended_action"].upper()):
                        deterministic_base["recommended_action"] = parsed["recommended_action"]
                return deterministic_base
        except Exception as e:
            logger.warning("Gemini API call failed for asset %s: %s. Using deterministic fallback.", asset_id, e)

        return deterministic_base

    def synthesize_portfolio_report(
        self,
        portfolio_stats: Dict[str, Any],
        asset_summaries: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        deterministic_base = self.fallback.synthesize_portfolio_report(portfolio_stats, asset_summaries)

        if not self.api_key:
            return deterministic_base

        deadline_val = portfolio_stats.get("earliest_migration_deadline_year")
        deadline_str = str(deadline_val) if deadline_val is not None else "Not established / Not applicable"

        prompt = PORTFOLIO_SYNTHESIS_USER_PROMPT_TEMPLATE.format(
            total_assets=portfolio_stats.get("total_assets", len(asset_summaries)),
            critical_count=portfolio_stats.get("critical_risk_count", 0),
            high_count=portfolio_stats.get("high_risk_count", 0),
            hndl_count=portfolio_stats.get("hndl_exposed_count", 0),
            mosca_count=portfolio_stats.get("mosca_deficit_count", 0),
            overdue_count=portfolio_stats.get("overdue_migration_count", 0),
            earliest_deadline=deadline_str,
            assets_summary_json=json.dumps(asset_summaries[:20], indent=2),
        )

        try:
            raw_text = self._call_gemini(prompt)
            parsed = clean_llm_json(raw_text)
            if parsed and "executive_summary" in parsed:
                # Guard against hallucinating "deadline of None"
                exec_sum = str(parsed["executive_summary"])
                if "deadline of None" in exec_sum or "deadline of none" in exec_sum:
                    exec_sum = exec_sum.replace("deadline of None", "unestablished deadline").replace("deadline of none", "unestablished deadline")
                deterministic_base["executive_summary"] = exec_sum
                if "key_findings" in parsed and isinstance(parsed["key_findings"], list):
                    deterministic_base["key_findings"] = parsed["key_findings"]
                return deterministic_base
        except Exception as e:
            logger.warning("Gemini portfolio synthesis failed: %s. Using fallback.", e)

        return deterministic_base

    def _call_gemini(self, prompt: str) -> str:
        last_error = None
        for model_name in self.candidate_models:
            # Try google-genai first
            try:
                from google import genai
                from google.genai import types

                client = genai.Client(api_key=self.api_key)
                response = client.models.generate_content(
                    model=model_name,
                    contents=f"{FINAL_REPORT_SYNTHESIS_SYSTEM_PROMPT}\n\n{prompt}",
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        temperature=0.1,
                    ),
                )
                if response.text:
                    self.model = model_name
                    return response.text
            except ImportError:
                pass
            except Exception as e:
                last_error = e
                logger.debug("google.genai call failed for model %s: %s", model_name, e)

            # Try google.generativeai
            try:
                import google.generativeai as legacy_genai

                legacy_genai.configure(api_key=self.api_key)
                model_obj = legacy_genai.GenerativeModel(
                    model_name=model_name,
                    system_instruction=FINAL_REPORT_SYNTHESIS_SYSTEM_PROMPT,
                    generation_config={"response_mime_type": "application/json", "temperature": 0.1},
                )
                resp = model_obj.generate_content(prompt)
                if resp.text:
                    self.model = model_name
                    return resp.text
            except Exception as e:
                last_error = e
                logger.debug("google.generativeai call failed for model %s: %s", model_name, e)

        if last_error:
            raise last_error
        return ""
