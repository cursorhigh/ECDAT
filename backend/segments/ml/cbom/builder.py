"""
CBOM Builder Component (builder.py)

Assembles processed, validated cryptographic assets and repository metadata into:
1. Official OWASP CycloneDX 1.6 CBOM document (specVersion 1.6 with 'cryptoProperties')
2. ECDAT Enhanced Hybrid CBOM document with rich summary statistics and explainability provenance
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Union

from .cyclonedx_schema import (
    CycloneDX16CBOM,
    Metadata,
    ToolComponent,
    CryptoComponent,
    CryptoProperties,
    AlgorithmProperties,
    ProtocolProperties,
    Evidence,
    Occurrence,
    Property,
)


class CBOMBuilder:
    """
    Assembles repository metadata, summary statistics, and cryptographic assets into
    CycloneDX 1.6 and ECDAT CBOM documents.
    """

    def __init__(self, format_name: str = "ECDAT-CBOM", version: str = "1.0"):
        self.format_name = format_name
        self.version = version

    def build_cyclonedx_1_6(
        self,
        repository: Optional[Dict[str, Any]] = None,
        crypto_assets: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Builds an official OWASP CycloneDX v1.6 compliant Cryptography Bill of Materials.

        :param repository: Target repository or system metadata.
        :param crypto_assets: List of extracted and validated cryptographic assets.
        :return: Standard CycloneDX 1.6 dictionary.
        """
        repo_data = repository or {}
        assets_data = crypto_assets or []
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        serial_number = f"urn:uuid:{uuid.uuid4()}"

        components: List[Dict[str, Any]] = []

        for idx, asset in enumerate(assets_data, start=1):
            if not isinstance(asset, dict):
                continue

            asset_id = asset.get("asset_id") or f"crypto-asset-{idx:04d}"
            algo_name = asset.get("algorithm") or "Unknown-Algorithm"
            family = asset.get("family") or "unknown"
            asset_type = asset.get("asset_type") or ("protocol" if family == "protocol" else "algorithm")

            # 1. Build Algorithm Properties
            params = asset.get("parameters", {}) if isinstance(asset.get("parameters"), dict) else {}
            key_size = params.get("key_size") or asset.get("key_size")
            curve = params.get("curve") or asset.get("curve")
            mode = params.get("mode") or asset.get("mode")
            padding = params.get("padding") or asset.get("padding")
            
            crypto_spec = asset.get("crypto_properties", {}) if isinstance(asset.get("crypto_properties"), dict) else {}
            primitive = crypto_spec.get("primitive") or asset.get("primitive") or family
            crypto_functions = crypto_spec.get("crypto_functions") or asset.get("crypto_functions") or []
            classical_sec = crypto_spec.get("classical_security_bits") or asset.get("classical_security_bits")
            nist_quantum = crypto_spec.get("nist_quantum_level")
            if nist_quantum is None:
                nist_quantum = asset.get("nist_quantum_level")

            library = asset.get("crypto_library") or asset.get("library")
            implementation = asset.get("implementation")

            algorithm_props = {
                "primitive": primitive,
                "parameterSetIdentifier": str(key_size) if key_size is not None else None,
                "curve": curve,
                "executionEnvironment": "software-plain",
                "implementationPlatform": library or implementation,
                "certificationLevel": "none",
                "mode": mode,
                "padding": padding,
                "cryptoFunctions": crypto_functions,
                "classicalSecurityLevel": classical_sec,
                "nistQuantumSecurityLevel": nist_quantum,
            }

            # 2. Build Protocol Properties if applicable
            protocol_props = None
            if asset_type == "protocol" or family == "protocol":
                protocol_props = {
                    "type": asset.get("protocol") or algo_name,
                    "version": "1.3" if "1.3" in str(algo_name) else ("1.2" if "1.2" in str(algo_name) else None),
                    "cipherSuites": [algo_name] if "AES" in str(algo_name) or "TLS" in str(algo_name) else [],
                }

            # 3. Build Evidence Occurrences
            location = asset.get("location", {}) if isinstance(asset.get("location"), dict) else {}
            occurrences = []
            if location.get("file"):
                occurrences.append({
                    "location": location.get("file"),
                    "line": location.get("line"),
                    "additionalContext": asset.get("evidence"),
                    "symbol": implementation,
                })

            # 4. Build Custom ECDAT Extension Properties (Provenance & Quantum facts)
            exp = asset.get("explainability", {}) if isinstance(asset.get("explainability"), dict) else {}
            properties = [
                {"name": "ecdat:validation_status", "value": str(asset.get("validation_status", "confirmed"))},
                {"name": "ecdat:detection_method", "value": str(exp.get("detection_method") or asset.get("detection_method", "deterministic"))},
                {"name": "ecdat:confidence", "value": str(asset.get("confidence", 0.95))},
                {"name": "ecdat:quantum_vulnerable", "value": str(crypto_spec.get("quantum_vulnerable", asset.get("quantum_vulnerable", False))).lower()},
                {"name": "ecdat:quantum_attack_type", "value": str(crypto_spec.get("quantum_attack_type", asset.get("quantum_attack_type", "None known")))},
                {"name": "ecdat:deprecated_or_disallowed", "value": str(crypto_spec.get("deprecated_or_disallowed", asset.get("deprecated_or_disallowed", False))).lower()},
            ]

            comp = {
                "type": "cryptographic-asset",
                "bom-ref": f"crypto-asset-{asset_id}-{algo_name.lower().replace(' ', '-')}",
                "name": algo_name,
                "description": asset.get("purpose") or f"{algo_name} cryptographic asset",
                "evidence": {"occurrences": occurrences} if occurrences else None,
                "cryptoProperties": {
                    "assetType": asset_type,
                    "algorithmProperties": algorithm_props if asset_type == "algorithm" else None,
                    "protocolProperties": protocol_props if asset_type == "protocol" else None,
                    "oid": crypto_spec.get("oid") or asset.get("oid"),
                },
                "properties": properties,
            }
            components.append(comp)

        bom_document = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": serial_number,
            "version": 1,
            "metadata": {
                "timestamp": timestamp,
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": "ECDAT-Discovery-CBOM-Agent",
                            "version": "1.1.0",
                        }
                    ]
                },
                "component": {
                    "type": "application",
                    "name": repo_data.get("name") or "cryptographic-target",
                },
            },
            "components": components,
        }

        return bom_document

    def build(
        self,
        repository: Optional[Dict[str, Any]] = None,
        crypto_assets: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Builds the ECDAT Hybrid CBOM document containing summary statistics, explainability,
        and embedded CycloneDX 1.6 compliance structure.

        :param repository: Repository metadata dictionary.
        :param crypto_assets: List of validated cryptographic asset dictionaries.
        :return: Final ECDAT CBOM dictionary object.
        """
        repo_data = repository or {}
        assets_data = crypto_assets or []

        # 1. Compute summary statistics
        total_assets = len(assets_data)
        confirmed_count = sum(1 for a in assets_data if a.get("validation_status") == "confirmed")
        partial_count = sum(1 for a in assets_data if a.get("validation_status") == "partial")
        needs_review_count = sum(1 for a in assets_data if a.get("validation_status") == "needs_review")
        invalid_count = sum(1 for a in assets_data if a.get("validation_status") == "invalid")

        # 2. Compute family counts
        family_counts = {
            "asymmetric": 0,
            "symmetric": 0,
            "hash": 0,
            "protocol": 0,
            "pqc": 0,
            "other": 0,
        }

        for asset in assets_data:
            fam = str(asset.get("family") or "").lower()
            if fam in family_counts:
                family_counts[fam] += 1
            else:
                family_counts["other"] += 1

        # 3. Construct ISO 8601 timestamp
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # 4. Generate embedded CycloneDX 1.6 representation
        cyclonedx_bom = self.build_cyclonedx_1_6(repository=repo_data, crypto_assets=assets_data)

        cbom_document: Dict[str, Any] = {
            "format": self.format_name,
            "version": self.version,
            "spec_version": "1.6-CycloneDX",
            "generated_at": generated_at,
            "repository": {
                "name": repo_data.get("name"),
                "url": repo_data.get("url"),
            },
            "summary": {
                "total_assets": total_assets,
                "confirmed_assets": confirmed_count,
                "partial_assets": partial_count,
                "needs_review_assets": needs_review_count,
                "invalid_assets": invalid_count,
                "by_family": family_counts,
            },
            "crypto_assets": assets_data,
            "cyclonedx_bom": cyclonedx_bom,
        }

        return cbom_document

    def save_json(
        self, cbom_doc: Dict[str, Any], output_path: Union[str, Path]
    ) -> Path:
        """
        Saves the CBOM dictionary object to a JSON file.

        :param cbom_doc: Validated CBOM dictionary.
        :param output_path: Output file path.
        :return: Path object of the saved JSON file.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cbom_doc, f, indent=2, ensure_ascii=False)
        return path
