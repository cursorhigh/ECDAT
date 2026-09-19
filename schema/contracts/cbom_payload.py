"""Handoff contract: CBOM document + per-asset risk assessment.

Boundary:  ml (analysis) -> mitigation
Storage:   analysis.AnalysisRun.cbom_document / risk_context

Documentation-of-record: the runtime pipeline is not wired to this contract
yet (see schema/README.md). It mirrors the CBOM document produced by
`cbom.builder.CBOMBuilder.build(...)` and persisted on `AnalysisRun`.
"""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

ValidationStatus = Literal["confirmed", "partial", "needs_review", "invalid"]


class RepositoryMeta(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None


class CBOMSummary(BaseModel):
    total_assets: int = 0
    confirmed_assets: int = 0
    partial_assets: int = 0
    needs_review_assets: int = 0
    invalid_assets: int = 0
    by_family: dict[str, int] = Field(default_factory=dict)


class CBOMAsset(BaseModel):
    """One asset entry inside `crypto_assets`."""

    model_config = {"extra": "allow"}

    name: str = ""
    family: str = ""
    algorithm: str = ""
    key_size: Optional[int] = None
    curve: str = ""
    protocol: str = ""
    library: str = ""
    library_version: str = ""
    validation_status: ValidationStatus = "needs_review"
    confidence: Optional[float] = None
    explanation: Optional[str] = None


class CBOMPayload(BaseModel):
    """The full CBOM document (analysis -> mitigation handoff)."""

    model_config = {"extra": "allow"}

    format: str = "ECDAT-CBOM"
    version: str = "1.0"
    generated_at: str = ""
    repository: RepositoryMeta = Field(default_factory=RepositoryMeta)
    summary: CBOMSummary = Field(default_factory=CBOMSummary)
    crypto_assets: list[CBOMAsset | dict[str, Any]] = Field(default_factory=list)