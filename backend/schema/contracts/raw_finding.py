"""Handoff contract: raw / normalized crypto-discovery findings.

Boundary:  scraping (ingest) -> ml (analysis)
Storage:   discovery.RawFinding.raw_json / discovery.NormalizedFinding rows

This contract is enforced at the ingest boundary: `discovery.services`
validates incoming payloads with these models before anything is persisted, so
a malformed import is reported instead of raising mid-pipeline.
"""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, model_validator

# Canonical algorithm families (mirrors discovery.models.NormalizedFinding).
_ALGORITHM_FAMILIES = frozenset(
    {
        "rsa",
        "ecc",
        "dsa",
        "dh",
        "aes",
        "des3",
        "hash",
        "mac",
        "pqc",
        "unknown",
    }
)

AlgorithmFamily = Literal[
    "rsa",
    "ecc",
    "dsa",
    "dh",
    "aes",
    "des3",
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

# Guard rails so a hostile or accidental export cannot exhaust the service.
MAX_LOCATION_LENGTH = 1024
MAX_FINDINGS_PER_IMPORT = 100_000


class RawFindingPayload(BaseModel):
    """A single finding dict as emitted by a scanner into `RawFinding.raw_json`."""

    model_config = {"extra": "allow"}

    location: str = Field(
        ...,
        max_length=MAX_LOCATION_LENGTH,
        description="File path / URI / cert store entry the finding was found at.",
    )
    # Absolute path the scanner read from disk, when it did. Distinct from
    # `location`, which is a display label in quick/whole scope and so cannot be
    # re-opened. Optional because externally imported findings have no local
    # file behind them.
    source_path: str = Field(
        default="",
        max_length=MAX_LOCATION_LENGTH,
        description="Absolute filesystem path this finding was read from, if any.",
    )
    # Not required: discovery normalizes an absent family by inferring it from
    # the algorithm, and records `unknown` when neither is conclusive.
    #
    # Typed as `str` rather than the Literal so the cross-field rule below can
    # run: a pydantic Literal rejects during field validation, before any
    # model-level validator gets a chance to see `kind`.
    family: str = "unknown"
    # What kind of artefact this is. Discovery must be able to say "this is a
    # certificate" or "this is a key reference" without collapsing everything
    # into an algorithm family.
    kind: str = "algorithm"
    algorithm: str = ""
    key_size: Optional[int] = Field(default=None, ge=1, le=1_000_000)
    curve: str = ""
    protocol: str = ""
    library: str = ""
    library_version: str = ""
    kind_hint: Optional[str] = None  # e.g. "public_key", "private_key", "protocol"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    line: Optional[int] = Field(default=None, ge=1, le=100_000_000)
    # Why ECDAT believes this exists. Must never contain secret material:
    # private keys are represented by a fingerprint, never by their bytes.
    evidence: Optional[dict[str, Any]] = None
    raw: Optional[dict[str, Any]] = None  # source evidence, e.g. {"matches": 3}

    @model_validator(mode="after")
    def _family_only_applies_to_algorithms(self):
        """Enforce that `family` names a real algorithm family.

        `family` describes an algorithm, so it only applies to algorithm
        findings. A certificate, protocol, dependency, or key reference has no
        algorithm family by definition: a detector that supplies one (or reuses
        a bucket like "protocol") is normalised to `unknown` rather than
        rejected, because `kind` already carries the meaning and losing the
        whole finding over a cosmetic field would be the worse outcome. For an
        algorithm finding an unrecognised family is a genuine error.
        """
        family = (self.family or "").strip().lower()

        if family in _ALGORITHM_FAMILIES:
            self.family = family
            return self

        if self.kind == "algorithm":
            raise ValueError(
                f"family must be one of {sorted(_ALGORITHM_FAMILIES)}, got {self.family!r}"
            )

        self.family = "unknown"
        return self


class NormalizedFindingPayload(BaseModel):
    """Canonical representation produced by discovery.normalizer."""

    model_config = {"extra": "allow"}

    raw_finding_id: int
    family: AlgorithmFamily
    algorithm: str = ""
    key_size: Optional[int] = Field(default=None, ge=1, le=1_000_000)
    curve: str = ""
    protocol: str = ""
    library: str = ""
    library_version: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    dedup_key: str = ""


class ScanIngestPayload(BaseModel):
    """Body accepted by the scraping segment's external ingest API.

    `mode` is deliberately absent: the data boundary is chosen by the service
    from its own configuration, never by the caller.
    """

    source_type: SourceType
    target: str = Field(default="", max_length=512)
    findings: list[RawFindingPayload] = Field(
        default_factory=list, max_length=MAX_FINDINGS_PER_IMPORT
    )