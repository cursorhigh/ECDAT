"""
CBOM Agent Component (cbom_agent.py)

Processes raw pre-discovered cryptographic findings JSON from the Discovery module
and converts them into a structured, standards-compliant Cryptography Bill of Materials (CBOM) document
following deterministic extraction, NIST/FIPS crypto catalog enrichment, AI-assisted reasoning fallback,
field-level explainability provenance, and strict quality validation.
"""

from typing import Dict, Any, List, Optional
from .builder import CBOMBuilder
from .validator import CBOMValidator
from .extractor import DeterministicExtractor
from .explainability import CBOMExplainabilityBuilder
from .ai_provider import BaseLLMProvider, get_llm_provider


def format_cbom_explanation(asset: Dict[str, Any]) -> str:
    """
    Formats a terminal-friendly CBOM Entry Explanation text block.

    :param asset: Cryptographic asset dictionary containing 'explainability'.
    :return: Formatted text string.
    """
    exp = asset.get("explainability", {}) if isinstance(asset.get("explainability"), dict) else {}
    asset_id = asset.get("asset_id") or "UNKNOWN"
    algo_name = asset.get("algorithm") or asset.get("family") or "Unknown Asset"

    method_raw = str(exp.get("method") or exp.get("detection_method") or "deterministic").upper()
    ai_used = exp.get("ai_used", False)
    ai_used_str = "YES" if ai_used else "NO"

    decision_reason = exp.get("decision_reason") or exp.get("summary") or "Known cryptographic API pattern matched."
    evidence_snippet = asset.get("evidence") or ""
    if not evidence_snippet:
        loc = asset.get("location", {})
        evidence_snippet = f"File: {loc.get('file', 'N/A')}, Line: {loc.get('line', 'N/A')}"

    field_evidences = exp.get("field_evidence") or exp.get("evidence") or []
    field_lines = []
    if isinstance(field_evidences, list) and field_evidences:
        for item in field_evidences:
            if isinstance(item, dict) and item.get("field") and item.get("value") is not None:
                field_lines.append(f"→ {item['field']} = {item['value']}")

    if not field_lines:
        field_lines.append(f"→ algorithm = {algo_name}")
        params = asset.get("parameters", {})
        if isinstance(params, dict):
            for k, v in params.items():
                if v is not None:
                    field_lines.append(f"→ {k} = {v}")

    fields_block = "\n".join(field_lines)
    conf_reason = exp.get("confidence_reason") or "High confidence because explicit cryptographic evidence was found."

    output = f"""[{asset_id}] {algo_name}

Detection Method: {method_raw}
AI Used: {ai_used_str}

Why:
{decision_reason}

Evidence:
→ {evidence_snippet}

Extracted Fields:
{fields_block}

Confidence Reason:
{conf_reason}"""
    return output.strip()


class CBOMAgent:
    """
    CBOM Agent for transforming discovery findings into structured CycloneDX 1.6 and ECDAT CBOM documents.
    Uses deterministic extraction and NIST/FIPS catalog lookup first, falling back to LLM assistance
    when critical context is missing or ambiguous.
    Applies quality validation and attaches field-level explainability provenance to every asset.
    """

    def __init__(self, llm_provider: Optional[BaseLLMProvider] = None):
        self.builder = CBOMBuilder()
        self.validator = CBOMValidator()
        self.extractor = DeterministicExtractor()
        self.explainability_builder = CBOMExplainabilityBuilder()
        self.llm_provider = llm_provider or get_llm_provider()

    def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes Discovery-style JSON data and converts it into a structured CBOM JSON object
        containing both ECDAT summary statistics and embedded CycloneDX 1.6 BOM representation.

        :param data: Input dictionary containing repository metadata and findings.
        :return: Structured CBOM dictionary object.
        """
        if not isinstance(data, dict):
            data = {}

        # 1. Read repository metadata
        raw_repo = data.get("repository") or data.get("target") or data.get("scan_metadata", {}).get("target") or {}
        if not isinstance(raw_repo, dict):
            raw_repo = {}

        repository_metadata = {
            "name": raw_repo.get("name") or "cryptographic-project",
            "url": raw_repo.get("url") or raw_repo.get("repository_url") or "",
        }

        # 2. Read findings list
        raw_findings = data.get("findings")
        if not isinstance(raw_findings, list):
            raw_findings = data.get("source_findings", [])

        # 3. Iterate through findings and enrich with deterministic extraction + catalog lookup
        crypto_assets: List[Dict[str, Any]] = []

        for finding in raw_findings:
            if not isinstance(finding, dict):
                continue

            # Step A: Run deterministic extraction & catalog lookup
            extracted = self.extractor.extract(finding)
            ai_was_used = False

            # Step B: Check if important information is missing and code evidence is available
            if self._is_information_missing(extracted, finding):
                ai_was_used = True
                ai_extracted = self.llm_provider.extract_metadata(finding, extracted)
                explainability = self.explainability_builder.build_ai_explanation(
                    finding=finding,
                    deterministic_result=extracted,
                    ai_result=ai_extracted,
                )
                extracted = self._merge_extraction_results(extracted, ai_extracted, explainability)
            else:
                explainability = self.explainability_builder.build_deterministic_explanation(
                    finding=finding,
                    deterministic_result=extracted,
                )
                extracted["explainability"] = explainability

            # Extract location (preserving file and line)
            file_path = finding.get("file")
            line_num = finding.get("line")
            if isinstance(finding.get("location"), dict):
                file_path = finding["location"].get("file", file_path)
                line_num = finding["location"].get("line", line_num)

            # Construct parameters dictionary
            parameters = {
                "key_size": extracted.get("key_size"),
                "mode": extracted.get("mode"),
                "curve": extracted.get("curve"),
                "padding": extracted.get("padding"),
                "hash": extracted.get("hash"),
            }
            if isinstance(finding.get("parameters"), dict):
                for k, v in finding["parameters"].items():
                    if v is not None or k not in parameters:
                        parameters[k] = v

            # Calculate confidence score
            confidence = finding.get("confidence")
            if confidence is None:
                confidence = extracted.get("confidence", 0.95 if not ai_was_used else 0.85)

            # Structured crypto properties block
            crypto_props = {
                "primitive": extracted.get("primitive"),
                "crypto_role": extracted.get("crypto_role"),
                "crypto_functions": extracted.get("crypto_functions", []),
                "classical_security_bits": extracted.get("classical_security_bits"),
                "nist_quantum_level": extracted.get("nist_quantum_level"),
                "quantum_vulnerable": extracted.get("quantum_vulnerable"),
                "quantum_attack_type": extracted.get("quantum_attack_type"),
                "deprecated_or_disallowed": extracted.get("deprecated_or_disallowed"),
                "oid": extracted.get("oid"),
            }

            asset_id = finding.get("id") or finding.get("asset_id")
            if not asset_id:
                asset_id = f"crypto-asset-{len(crypto_assets)+1:03d}"

            asset = {
                "asset_id": asset_id,
                "asset_type": extracted["asset_type"],
                "algorithm": finding.get("algorithm") or finding.get("detected") or extracted.get("algorithm") or "unknown",
                "family": extracted["family"],
                "parameters": parameters,
                "protocol": extracted.get("protocol"),
                "crypto_library": extracted.get("crypto_library"),
                "purpose": finding.get("purpose") or extracted.get("purpose"),
                "implementation": finding.get("implementation") or finding.get("library") or extracted.get("implementation"),
                "location": {
                    "file": file_path,
                    "line": line_num,
                },
                "evidence": finding.get("code") or finding.get("evidence"),
                "confidence": float(confidence),
                "validation_status": finding.get("validation_status") or "unvalidated",
                "crypto_properties": crypto_props,
                "explainability": explainability,
                # Operational & threat context propagation
                "exposure": finding.get("exposure") or finding.get("network_exposure"),
                "network_exposure": finding.get("network_exposure") or finding.get("exposure"),
                "public_endpoint": bool(finding.get("public_endpoint") or finding.get("internet_facing")),
                "internet_facing": bool(finding.get("internet_facing") or finding.get("public_endpoint")),
                "hndl_exposure": finding.get("hndl_exposure") or finding.get("hndl_risk"),
                "hndl_risk": finding.get("hndl_risk") or finding.get("hndl_exposure"),
                "data_shelf_life_years": finding.get("data_shelf_life_years") or finding.get("data_lifetime_years"),
                "data_lifetime_years": finding.get("data_lifetime_years") or finding.get("data_shelf_life_years"),
                "data_sensitivity": finding.get("data_sensitivity"),
                "migration_time_years": finding.get("migration_time_years"),
                "quantum_horizon_years": finding.get("quantum_horizon_years"),
                "role": finding.get("role") or finding.get("purpose") or extracted.get("crypto_role"),
                "exploitability_score": finding.get("exploitability_score"),
            }

            # Step C: Quality validation
            asset = self.validator.validate_asset(asset)
            crypto_assets.append(asset)

        # 4. Build structured CBOM document
        cbom_document = self.builder.build(
            repository=repository_metadata,
            crypto_assets=crypto_assets,
        )

        # 5. Validate generated CBOM
        is_valid, errors = self.validator.validate(cbom_document)
        if not is_valid:
            raise ValueError(f"CBOM validation failed: {errors}")

        return cbom_document

    def generate_cbom(
        self, data: Dict[str, Any], output_filepath: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Full pipeline: Processes findings into validated CBOM dictionary object,
        and optionally saves it to a JSON file.

        :param data: Discovery findings JSON object.
        :param output_filepath: Optional path to save CBOM JSON file.
        :return: CBOM dictionary object.
        """
        cbom_doc = self.process(data)
        if output_filepath:
            self.builder.save_json(cbom_doc, output_filepath)
        return cbom_doc

    def generate_cyclonedx_cbom(
        self, data: Dict[str, Any], output_filepath: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Processes findings and returns/saves a standalone CycloneDX 1.6 CBOM document.

        :param data: Discovery findings JSON object.
        :param output_filepath: Optional path to save CycloneDX JSON file.
        :return: CycloneDX 1.6 BOM dictionary object.
        """
        cbom_doc = self.process(data)
        cdx_bom = cbom_doc.get("cyclonedx_bom", {})
        if output_filepath:
            self.builder.save_json(cdx_bom, output_filepath)
        return cdx_bom

    def _is_information_missing(
        self, extracted: Dict[str, Any], finding: Dict[str, Any]
    ) -> bool:
        """
        Determines whether deterministic extraction was insufficient, triggering LLM assistance.
        Triggered if family or asset_type is unknown/ambiguous, or if detected was marked UNKNOWN.
        """
        evidence = finding.get("code") or finding.get("evidence")
        if not evidence:
            return False

        detected_raw = str(finding.get("detected") or "").upper()

        return (
            extracted.get("family") == "unknown"
            or extracted.get("asset_type") == "unknown"
            or detected_raw == "UNKNOWN"
            or detected_raw == "UNKNOWN CRYPTOGRAPHIC ASSET"
        )

    def _merge_extraction_results(
        self,
        deterministic: Dict[str, Any],
        ai_results: Dict[str, Any],
        explainability: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Merges AI results into deterministic results without overwriting non-null deterministic data.
        """
        if not isinstance(ai_results, dict):
            deterministic["explainability"] = explainability
            return deterministic

        merged = dict(deterministic)

        # Merge core properties
        for key in [
            "family",
            "asset_type",
            "purpose",
            "implementation",
            "key_size",
            "mode",
            "curve",
            "hash",
            "algorithm",
        ]:
            val = ai_results.get(key)
            if val is not None and (merged.get(key) is None or merged.get(key) == "unknown"):
                merged[key] = val

        merged["explainability"] = explainability

        if ai_results.get("confidence") is not None:
            merged["confidence"] = ai_results["confidence"]

        return merged
