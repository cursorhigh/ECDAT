"""
CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) Schema Models

Implements the official OWASP CycloneDX v1.6 specification with 'cryptoProperties'
for cryptographic components, algorithms, certificates, protocols, and evidence occurrences.
"""

from __future__ import annotations
from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field, ConfigDict


class AlgorithmProperties(BaseModel):
    """CycloneDX 1.6 Algorithm Properties."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    primitive: Optional[str] = Field(default=None, description="Cryptographic primitive category (e.g. asymmetric, symmetric, signature, digest)")
    parameterSetIdentifier: Optional[str] = Field(default=None, description="Key or parameter set size (e.g. '2048', '256', 'P-256')")
    curve: Optional[str] = Field(default=None, description="Elliptic curve name (e.g. 'secp256r1', 'Ed25519')")
    executionEnvironment: Optional[str] = Field(default="software-plain", description="Execution context (e.g. 'software-plain', 'hsm', 'tpm')")
    implementationPlatform: Optional[str] = Field(default=None, description="Cryptographic library or platform (e.g. 'OpenSSL', 'cryptography')")
    certificationLevel: Optional[str] = Field(default="none", description="FIPS 140 or CC certification level")
    mode: Optional[str] = Field(default=None, description="Cipher mode (e.g. 'GCM', 'CBC', 'CTR')")
    padding: Optional[str] = Field(default=None, description="Padding scheme (e.g. 'OAEP', 'PSS', 'PKCS1v1.5', 'PKCS7')")
    cryptoFunctions: List[str] = Field(default_factory=list, description="Operations supported (e.g. ['sign', 'verify'])")
    classicalSecurityLevel: Optional[int] = Field(default=None, description="Estimated classical bit security (0-512)")
    nistQuantumSecurityLevel: Optional[int] = Field(default=None, description="NIST PQC Security Category (0-5)")


class ProtocolProperties(BaseModel):
    """CycloneDX 1.6 Protocol Properties."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    type: Optional[str] = Field(default=None, description="Protocol type (e.g. 'tls', 'ssh', 'ipsec')")
    version: Optional[str] = Field(default=None, description="Protocol version (e.g. '1.2', '1.3')")
    cipherSuites: List[str] = Field(default_factory=list, description="Configured or observed cipher suites")


class CertificateProperties(BaseModel):
    """CycloneDX 1.6 Certificate Properties."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    subjectName: Optional[str] = None
    issuerName: Optional[str] = None
    notValidBefore: Optional[str] = None
    notValidAfter: Optional[str] = None
    signatureAlgorithmRef: Optional[str] = None
    subjectPublicKeyRef: Optional[str] = None


class CryptoProperties(BaseModel):
    """CycloneDX 1.6 Top-level CryptoProperties Container."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    assetType: Literal["algorithm", "certificate", "protocol", "related-crypto-material"] = Field(
        default="algorithm",
        description="Type of cryptographic asset"
    )
    algorithmProperties: Optional[AlgorithmProperties] = None
    protocolProperties: Optional[ProtocolProperties] = None
    certificateProperties: Optional[CertificateProperties] = None
    oid: Optional[str] = Field(default=None, description="ASN.1 Object Identifier")


class Occurrence(BaseModel):
    """CycloneDX Evidence Occurrence Location."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    location: Optional[str] = Field(default=None, description="File path relative to repository root")
    line: Optional[int] = Field(default=None, description="1-indexed line number")
    offset: Optional[int] = Field(default=None, description="Character offset")
    symbol: Optional[str] = Field(default=None, description="Function or variable symbol")
    additionalContext: Optional[str] = Field(default=None, description="Snippet or call expression")


class Evidence(BaseModel):
    """CycloneDX 1.6 Evidence Container."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    occurrences: List[Occurrence] = Field(default_factory=list)


class Property(BaseModel):
    """Generic Name-Value Property for Extension Metadata."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    name: str
    value: str


class CryptoComponent(BaseModel):
    """CycloneDX 1.6 Cryptographic Asset Component."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    type: Literal["cryptographic-asset"] = "cryptographic-asset"
    bom_ref: str = Field(alias="bom-ref", description="Unique BOM reference identifier")
    name: str = Field(description="Canonical asset / algorithm name")
    description: Optional[str] = Field(default=None, description="Human readable description")
    evidence: Optional[Evidence] = None
    cryptoProperties: CryptoProperties
    properties: List[Property] = Field(default_factory=list, description="ECDAT provenance & quantum annotations")


class ToolComponent(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)
    type: str = "application"
    name: str = "ECDAT-Discovery-CBOM-Agent"
    version: str = "1.1.0"


class Metadata(BaseModel):
    """CycloneDX 1.6 Metadata."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    timestamp: str
    tools: Dict[str, Any] = Field(default_factory=lambda: {"components": [ToolComponent().model_dump()]})
    component: Optional[Dict[str, Any]] = None


class CycloneDX16CBOM(BaseModel):
    """Root CycloneDX 1.6 Cryptographic Bill of Materials Document."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    bomFormat: Literal["CycloneDX"] = "CycloneDX"
    specVersion: Literal["1.6"] = "1.6"
    serialNumber: str
    version: int = 1
    metadata: Metadata
    components: List[CryptoComponent] = Field(default_factory=list)
