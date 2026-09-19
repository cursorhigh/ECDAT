"""Handoff contract: mitigation plan document.

Boundary:  mitigation -> reporting
Storage:   mitigation.MitigationPlan.document

Documentation-of-record: the runtime pipeline is not wired to this contract
yet (see schema/README.md). It mirrors the JSON document produced by the
mitigation planner and rendered by the reporting segment.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class MitigationSummary(BaseModel):
    model_config = {"extra": "allow"}

    assets: int = 0
    wave1: int = 0
    wave2: int = 0
    wave3: int = 0
    quantum_vulnerable: int = 0
    priority_high: int = 0
    priority_medium: int = 0
    priority_low: int = 0


class MitigationAiContext(BaseModel):
    model_config = {"extra": "allow"}

    enhanced: bool = False
    model_provider: Optional[str] = None
    notes: list[str] = Field(default_factory=list)


class MitigationRow(BaseModel):
    """One asset migration recommendation in `rows`."""

    model_config = {"extra": "allow"}

    asset_id: Optional[Any] = None
    algorithm: str = ""
    family: str = ""
    key_size: Optional[int] = None
    risk: str = ""
    pqc_status: str = ""  # e.g. "quantum_vulnerable" / "pqc_ready"
    action: str = ""
    replacement: str = ""
    wave: int = 1
    priority: str = ""


class MitigationPlanPayload(BaseModel):
    """The full mitigation plan document (mitigation -> reporting handoff)."""

    model_config = {"extra": "allow"}

    version: str = "1.0"
    generated_at: str = ""
    summary: MitigationSummary = Field(default_factory=MitigationSummary)
    rows: list[MitigationRow | dict[str, Any]] = Field(default_factory=list)
    ai_context: MitigationAiContext = Field(default_factory=MitigationAiContext)