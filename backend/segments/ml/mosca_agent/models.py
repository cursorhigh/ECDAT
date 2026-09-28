"""
MOSCA+ Theorem Data Models (models.py)

Strict Pydantic models modeling Michele Mosca's Theorem of Quantum Risk (X + Y > Z):
- X: Migration Time (years)
- Y: Data Shelf Life / Confidentiality Requirement (years)
- Z: Time to CRQC / Quantum Threat Horizon (years)
- Delta M: Mosca Deficit / Safety Margin (years)
- T_deadline: Migration Start Deadline Year
"""

from __future__ import annotations
from typing import Dict, Any, List, Optional, Literal, Union
from pydantic import BaseModel, Field, ConfigDict


class MoscaVariables(BaseModel):
    """Core mathematical variables of Mosca's inequality."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    X_migration_time_years: float = Field(description="Time required to migrate to post-quantum cryptography (X)")
    Y_data_lifetime_years: float = Field(description="Time data must remain confidential/secure (Y)")
    Z_time_to_crqc_years: float = Field(description="Time until a cryptanalytically relevant quantum computer arrives (Z)")
    X_plus_Y: float = Field(description="Sum of migration time and data lifetime (X + Y)")


class MoscaTimelineMetrics(BaseModel):
    """Timeline and deadline projections derived from Mosca variables."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    assessment_year: int = Field(default=2026, description="Year when the assessment is performed")
    projected_crqc_year: int = Field(default=2033, description="Assumed CRQC threat horizon arrival year")
    migration_completion_year: float = Field(description="Year migration completes if started today (assessment_year + X)")
    data_expiry_year: float = Field(description="Year data confidentiality expires (assessment_year + Y)")
    mosca_deficit_years: float = Field(description="Mosca deficit window or safety margin: (X + Y) - Z")
    must_start_by_year: float = Field(description="Latest year migration must start to avoid a quantum deficit: assessment_year + Z - X")
    is_overdue_to_start: bool = Field(description="True if must_start_by_year <= assessment_year (migration is overdue)")


class MoscaThreatVectors(BaseModel):
    """Decomposed threat and impact multipliers."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    crypto_susceptibility: float = Field(description="Cryptographic vulnerability score (0.0 to 1.0)")
    impact_multiplier: float = Field(description="Normalized data sensitivity & business criticality multiplier (0.2 to 1.0)")
    crypto_agility_score: int = Field(default=3, description="Agility level (1 = hardcoded, 5 = fully agile)")
    migration_complexity_score: int = Field(default=3, description="Migration complexity (1 = trivial, 5 = extreme)")


class MoscaScenarioAssumptions(BaseModel):
    """Provenance metadata documenting scenario parameters."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    quantum_horizon_year: int = Field(default=2033, description="Assumed CRQC threat horizon arrival year")
    quantum_horizon_type: Literal["SCENARIO_ASSUMPTION"] = "SCENARIO_ASSUMPTION"
    quantum_horizon_source: Literal["CONFIGURATION", "USER_OVERRIDE"] = Field(
        default="CONFIGURATION",
        description="Source of the quantum horizon assumption"
    )
    assessment_year: int = Field(default=2026, description="Configured baseline assessment year")


class MoscaAssessment(BaseModel):
    """Asset-level Mosca inequality assessment result."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    inequality_satisfied: bool = Field(description="True if X + Y > Z (quantum risk inequality holds)")
    mosca_risk_index: float = Field(description="Normalized Mosca risk index (0.0 to 1.0)")
    urgency_tier: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"] = Field(
        description="Action urgency classification"
    )
    migration_posture: Literal["MIGRATION_DEFICIT", "MIGRATION_OVERDUE", "SAFE_BUFFER", "QUANTUM_RESILIENT"] = Field(
        description="Categorical migration posture"
    )
    quantum_vulnerable: bool = Field(description="Whether the algorithm is vulnerable to quantum attacks")
    variables: MoscaVariables
    timeline: MoscaTimelineMetrics
    threat_vectors: MoscaThreatVectors
    assumptions: MoscaScenarioAssumptions
    reason: str = Field(description="Deterministic calculation rationale")
    migration_guidance: str = Field(description="Actionable mitigation recommendation")


class MoscaAssetReport(BaseModel):
    """Container pairing an asset identifier with its Mosca assessment."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    asset_id: str
    algorithm: str
    mosca: MoscaAssessment


class MoscaDocumentSummary(BaseModel):
    """Repository or application-level aggregated Mosca assessment summary."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    assessment_year: int = 2026
    total_assessed_assets: int
    inequality_satisfied_count: int
    overdue_assets_count: int
    overall_mosca_posture: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"]
    max_mosca_risk_index: float
    max_mosca_deficit_years: float
    by_urgency_tier: Dict[str, int]
    assumptions: MoscaScenarioAssumptions
    asset_assessments: List[MoscaAssetReport]
