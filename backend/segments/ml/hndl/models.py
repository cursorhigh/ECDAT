"""
HNDL (Harvest Now, Decrypt Later) Data Models (models.py)

Strict Pydantic models for HNDL timeline metrics, threat vectors, scenario assumptions,
per-asset assessments, and repository-level HNDL posture summaries.
"""

from __future__ import annotations
from typing import Dict, Any, List, Optional, Literal, Union
from pydantic import BaseModel, Field, ConfigDict


class HNDLTimelineMetrics(BaseModel):
    """Timeline metrics modeling data confidentiality lifetime vs. quantum threat horizon."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    assessment_year: int = Field(default=2026, description="Year when the assessment is performed")
    data_lifetime_years: float = Field(description="Years the data must remain confidential (Y)")
    data_expiry_year: float = Field(description="Calendar year when data confidentiality expires (assessment_year + Y)")
    projected_crqc_year: int = Field(default=2033, description="Configured quantum threat horizon year (CRQC arrival scenario)")
    exposure_window_years: float = Field(description="Years the data remains sensitive after quantum horizon arrives (max(0, expiry - CRQC))")
    compromised_while_sensitive: bool = Field(description="True if data remains sensitive beyond the assumed quantum horizon")
    timeline_factor: float = Field(description="Ratio of exposure window to total lifetime (min(1.0, exposure_window / lifetime))")


class HNDLThreatVectors(BaseModel):
    """Decomposed threat vector scores contributing to HNDL exposure."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    crypto_susceptibility: float = Field(description="Cryptographic vulnerability to quantum attacks (0.0 to 1.0)")
    harvestability_score: float = Field(description="Likelihood of adversary intercepting/storing ciphertext (0.0 to 1.0)")
    impact_multiplier: float = Field(description="Normalized data sensitivity & business criticality multiplier (0.2 to 1.0)")
    pfs_status: Literal["PFS_PRESENT", "LACK_OF_PFS", "UNKNOWN"] = Field(
        default="UNKNOWN",
        description="Ephemeral Perfect Forward Secrecy status"
    )


class HNDLScenarioAssumptions(BaseModel):
    """Explicit provenance metadata documenting scenario parameters."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    quantum_horizon_year: int = Field(default=2033, description="Assumed CRQC threat horizon year")
    quantum_horizon_type: Literal["SCENARIO_ASSUMPTION"] = "SCENARIO_ASSUMPTION"
    quantum_horizon_source: Literal["CONFIGURATION", "USER_OVERRIDE"] = Field(
        default="CONFIGURATION",
        description="Source of the quantum horizon assumption"
    )
    assessment_year: int = Field(default=2026, description="Configured baseline assessment year")


class HNDLAssessment(BaseModel):
    """Asset-level HNDL risk assessment result."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    applicable: bool = Field(description="True if HNDL is applicable under the configured scenario")
    hndl_exposure_score: float = Field(description="Composite HNDL exposure score (0.0 to 1.0)")
    urgency_tier: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"] = Field(
        description="Action urgency classification"
    )
    harvestability: Literal["HIGH", "MEDIUM", "LOW"] = Field(description="Categorical harvestability level")
    quantum_vulnerable: bool = Field(description="Whether the algorithm is vulnerable to quantum cryptanalysis")
    future_decryption_risk: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"] = Field(
        description="Severity of future retrospective decryption"
    )
    timeline: HNDLTimelineMetrics
    threat_vectors: HNDLThreatVectors
    assumptions: HNDLScenarioAssumptions
    reason: str = Field(description="Deterministic calculation rationale")
    mitigation_priority: str = Field(description="Actionable mitigation recommendation")


class HNDLAssetReport(BaseModel):
    """Container pairing an asset identifier with its HNDL assessment."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    asset_id: str
    algorithm: str
    hndl: HNDLAssessment


class HNDLDocumentSummary(BaseModel):
    """Repository or application-level aggregated HNDL assessment summary."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    assessment_year: int = 2026
    total_assessed_assets: int
    applicable_assets_count: int
    overall_hndl_posture: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"]
    max_hndl_exposure_score: float
    by_urgency_tier: Dict[str, int]
    assumptions: HNDLScenarioAssumptions
    asset_assessments: List[HNDLAssetReport]
