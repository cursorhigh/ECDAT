"""
Final Combined Result Data Models (models.py)

Defines Pydantic models for bundling inputs from CBOM, CatBoost ML Risk Model,
HNDL Timeline Engine, and Mosca Inequality Agent, as well as the synthesized
executive report output schemas with explicit source attributions, PQC classification,
policy overrides, and clean auditability.
"""

from typing import Dict, Any, List, Optional, Literal, Union
from pydantic import BaseModel, Field, ConfigDict


class AttributionEvidence(BaseModel):
    """
    Evidence record identifying which analysis engine contributed to a specific conclusion.
    """
    model_config = ConfigDict(extra="ignore")

    pillar: Literal["ML_RISK", "HNDL_ENGINE", "MOSCA_THEOREM", "CBOM_CATALOG", "POLICY_ENGINE"] = Field(
        ..., description="The analysis engine providing this insight"
    )
    metric_name: str = Field(..., description="Key metric or variable name (e.g. 'confidence', 'deficit_years', 'harvestability')")
    value: Union[str, float, int, bool, List[str], Dict[str, Any], None] = Field(
        ..., description="The observed value"
    )
    source_detail: str = Field(
        ..., description="Human-readable provenance citation explaining how this informed the conclusion"
    )


class AssetInputBundle(BaseModel):
    """
    Input bundle combining all upstream outputs for a single cryptographic asset.
    """
    model_config = ConfigDict(extra="ignore")

    asset_id: str = Field(..., description="Unique cryptographic asset identifier")
    algorithm: str = Field(..., description="Algorithm name (e.g. RSA-2048, AES-256-GCM)")
    cbom_asset: Dict[str, Any] = Field(default_factory=dict, description="Raw CBOM component dictionary")
    ml_risk_result: Optional[Dict[str, Any]] = Field(default=None, description="Output from CatBoost Quantum Risk Model")
    hndl_result: Optional[Dict[str, Any]] = Field(default=None, description="Output from HNDL Timeline Engine")
    mosca_result: Optional[Dict[str, Any]] = Field(default=None, description="Output from Mosca Inequality Agent")
    operational_context: Optional[Dict[str, Any]] = Field(default=None, description="Operational & business context")


class AssetSynthesisReport(BaseModel):
    """
    Synthesized final risk assessment report for an individual cryptographic asset.
    Strictly separates ML predictions, confidence, PQC classification, policy overrides,
    and unified risk scoring.
    """
    model_config = ConfigDict(extra="ignore")

    asset_id: str
    algorithm: str
    pqc_status: Literal[
        "PQC_NATIVE",
        "HYBRID_PQC",
        "SYMMETRIC_QUANTUM_RESILIENT",
        "SYMMETRIC_TRANSITIONAL",
        "CLASSICAL_VULNERABLE",
        "LEGACY_DEPRECATED",
    ] = Field(..., description="Normative PQC categorization")
    policy_status: str = Field("COMPLIANT", description="Cryptographic policy / compliance status")
    policy_overrides: List[str] = Field(default_factory=list, description="Explicit reasons for any policy override adjustments")
    
    # Risk Classifications
    base_risk_class: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"] = Field(
        ..., description="Risk class derived purely from the numerical unified score"
    )
    final_risk_class: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"] = Field(
        ..., description="Final risk tier after applying explicit policy overrides"
    )
    overall_quantum_risk_tier: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"] = Field(
        ..., description="Alias for final_risk_class for backward compatibility"
    )
    unified_risk_score: float = Field(
        ..., ge=0.0, le=100.0, description="Normalized risk score from 0 (Safe) to 100 (Immediate Critical Risk)"
    )
    
    # Migration Status & Deadlines
    migration_required: bool = Field(..., description="Whether post-quantum migration is mandatory")
    migration_deadline: Optional[Union[float, int, str]] = Field(
        None, description="Mandatory start deadline year (or null / 'N/A')"
    )
    urgency_tier: Literal["IMMEDIATE", "CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"] = Field(
        ..., description="Migration action urgency"
    )
    
    # Engine specific summary metrics
    ml_prediction: str = Field(..., description="Raw ML CatBoost predicted class")
    ml_confidence_pct: float = Field(..., description="Raw ML model confidence as a percentage (0.0 - 100.0%)")
    ml_summary: Dict[str, Any] = Field(default_factory=dict, description="ML CatBoost model predictions & top SHAP features")
    hndl_summary: Dict[str, Any] = Field(default_factory=dict, description="HNDL harvestability & timeline exposure")
    mosca_summary: Dict[str, Any] = Field(default_factory=dict, description="Mosca inequality timeline deficit & start deadline")
    
    # Narrative & Citations
    risk_drivers: List[str] = Field(default_factory=list, description="Explicit factors driving the risk")
    primary_risk_driver: str = Field(..., description="The predominant factor driving the risk")
    executive_narrative: str = Field(..., description="High-level synthesis narrative generated or formatted by Gemini")
    attributions: List[AttributionEvidence] = Field(
        default_factory=list, description="Explicit source citations mapping conclusions to ML, HNDL, and Mosca pillars"
    )
    recommended_action: str = Field(..., description="Prescriptive algorithm-tailored migration / remediation step")


class PortfolioSummaryStats(BaseModel):
    """
    Aggregated summary metrics across the entire application cryptographic inventory.
    """
    model_config = ConfigDict(extra="ignore")

    total_assets: int = 0
    critical_risk_count: int = 0
    high_risk_count: int = 0
    medium_risk_count: int = 0
    low_risk_count: int = 0
    negligible_risk_count: int = 0
    
    hndl_exposed_count: int = 0
    mosca_deficit_count: int = 0
    overdue_migration_count: int = 0
    
    average_risk_score: float = 0.0
    highest_risk_score: float = 0.0
    earliest_migration_deadline_year: Optional[Union[float, int]] = None


class FinalExecutiveReport(BaseModel):
    """
    Final comprehensive enterprise quantum risk assessment report combining ML, HNDL, and Mosca.
    """
    model_config = ConfigDict(extra="ignore")

    report_title: str = "ECDAT Enterprise Post-Quantum Cryptographic Risk Report"
    generated_at: str = Field(..., description="Timestamp of report generation")
    generation_provider: str = Field(
        ..., description="Engine used for narrative generation ('Google Gemini AI' or 'Deterministic Fallback Engine')"
    )
    portfolio_stats: PortfolioSummaryStats = Field(default_factory=PortfolioSummaryStats)
    executive_summary: str = Field(..., description="Executive-level summary of cryptographic posture")
    key_findings: List[str] = Field(default_factory=list, description="Key high-impact risk takeaways")
    asset_reports: List[AssetSynthesisReport] = Field(default_factory=list, description="Per-asset synthesized reports")
    source_attribution_summary: Dict[str, str] = Field(
        default_factory=dict, description="Summary of how ML, HNDL, and Mosca contributed to findings"
    )
