"""Handoff contract: raw / normalized crypto-discovery findings.

Boundary:  scraping (ingest) -> ml (analysis)
Storage:   discovery.RawFinding.raw_json / discovery.NormalizedFinding rows

Documentation-of-record: the runtime pipeline is not wired to this contract
yet (see schema/README.md). It mirrors `discovery` model fields exactly.
"""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

# Canonical algorithm families (mirrors discovery.models.NormalizedFinding).
AlgorithmFamily = Literal[
    "rsa",
    "ecc",
    "dsa",
    "dh",
    "aes",
    "hash",
    "mac",
    "pqc",
    "unknown",
]

# ScanJob.SourceType choices.
SourceType = Literal[
    "source_code",
    "binary",
    "dependency",
    "container",
    "certificate",
    "hsm",
    "cloud",
]


class RawFindingPayload(BaseModel):
    """A single finding dict as emitted by a scanner into `RawFinding.raw_json`."""

    model_config = {"extra": "allow"}

    location: str = Field(..., description="File path / URI / cert store entry the finding was found at.")
    family: AlgorithmFamily
    algorithm: str = ""
    key_size: Optional[int] = None
    curve: str = ""
    protocol: str = ""
    library: str = ""
    library_version: str = ""
    kind: Optional[str] = None  # e.g. "public_key", "private_key", "protocol"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    raw: Optional[dict[str, Any]] = None  # source evidence, e.g. {"matches": 3}


class NormalizedFindingPayload(BaseModel):
    """Canonical representation produced by discovery.normalizer."""

    model_config = {"extra": "allow"}

    raw_finding_id: int
    family: AlgorithmFamily
    algorithm: str = ""
    key_size: Optional[int] = None
    curve: str = ""
    protocol: str = ""
    library: str = ""
    library_version: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    dedup_key: str = ""


class ScanIngestPayload(BaseModel):
    """Body accepted by the scraping segment's external ingest API."""

    source_type: SourceType
    target: str
    mode: str = "actual"
    options: dict[str, Any] = Field(default_factory=dict)
    findings: list[RawFindingPayload] = Field(default_factory=list)