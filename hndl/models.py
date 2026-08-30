"""
HNDL Module Data Models & Schemas

Defines type annotations and structures for CBOM Cryptographic Assets,
Risk Contexts, and HNDL Threat Assessment results.
"""

from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field


@dataclass
class CBOMAlgorithm:
    family: str
    name: str


@dataclass
class CBOMParameters:
    key_size: Optional[int] = None
    mode: Optional[str] = None
    curve: Optional[str] = None
    hash: Optional[str] = None


@dataclass
class DataContext:
    sensitivity: str  # LOW, MEDIUM, HIGH, CRITICAL
    data_lifetime_years: int


@dataclass
class NetworkContext:
    internet_exposed: bool
    collectable: bool


@dataclass
class HNDLAssessmentResult:
    applicable: bool
    harvestability: str  # HIGH, MEDIUM, LOW
    future_decryption_risk: str  # HIGH, MEDIUM, LOW
    data_lifetime_years: int
    quantum_vulnerable: Optional[bool]
    reason: str


@dataclass
class HNDLReportPayload:
    asset_id: str
    hndl: HNDLAssessmentResult
