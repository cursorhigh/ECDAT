"""
CBOM Validator Component

Validates candidate cryptographic assets and full CBOM documents for structural completeness,
parameter validity, and algorithm/family logical consistency without mutating evidence or inventing corrections.

Assigns explicit validation statuses:
- 'confirmed': Complete, evidence-backed, and logically consistent.
- 'partial': Valid and consistent, but missing optional parameters or evidence.
- 'needs_review': Contradictory, inconsistent, or invalid parameter patterns detected.
- 'invalid': Structurally incomplete (missing asset_id or location file).

NOTE: Focused strictly on data quality. Does NOT assess quantum risk.
"""

from typing import Dict, Any, Tuple, List


class CBOMValidator:
    """
    Validates cryptographic assets for structural and semantic consistency.
    """

    REQUIRED_ASSET_FIELDS = [
        "asset_id",
        "asset_type",
        "algorithm",
        "family",
        "parameters",
        "purpose",
        "implementation",
        "location",
        "evidence",
        "confidence",
        "validation_status",
    ]

    ALLOWED_EVIDENCE_TYPES = {
        "explicit",
        "pattern_match",
        "inferred_from_provided_evidence",
        "insufficient",
    }

    KNOWN_FAMILIES = {
        "RSA": "asymmetric",
        "ECDSA": "asymmetric",
        "ECDH": "asymmetric",
        "ECC": "asymmetric",
        "ED25519": "asymmetric",
        "X25519": "asymmetric",
        "DSA": "asymmetric",
        "DH": "asymmetric",
        "AES": "symmetric",
        "AES-GCM": "symmetric",
        "AES-CBC": "symmetric",
        "DES": "symmetric",
        "3DES": "symmetric",
        "CHACHA20": "symmetric",
        "SHA-256": "hash",
        "SHA-512": "hash",
        "SHA-384": "hash",
        "SHA-1": "hash",
        "SHA-3": "hash",
        "MD5": "hash",
        "TLS": "protocol",
        "SSL": "protocol",
        "OPENSSL TLS": "protocol",
        "SSH": "protocol",
        "IPSEC": "protocol",
    }

    VALID_AES_MODES = {"GCM", "CBC", "CTR", "ECB", "CFB", "OFB", "CCM", "XTS"}

    def validate_asset(self, asset: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validates a single candidate cryptographic asset without mutating its values.
        Determines and sets asset['validation_status'].

        :param asset: Cryptographic asset dictionary.
        :return: Validated asset dictionary with updated 'validation_status'.
        """
        issues = []
        is_structurally_valid = True

        # 1. Structural Check
        if not asset.get("asset_id"):
            issues.append("Missing asset_id.")
            is_structurally_valid = False

        location = asset.get("location")
        if not isinstance(location, dict) or not location.get("file"):
            issues.append("Missing or invalid location file.")
            is_structurally_valid = False

        if not is_structurally_valid:
            asset["validation_status"] = "invalid"
            return asset

        # Validate explainability structure if present
        exp = asset.get("explainability")
        if exp is not None:
            if not isinstance(exp, dict):
                issues.append("Field 'explainability' must be a dictionary.")
            else:
                fe = exp.get("field_evidence") or exp.get("evidence")
                if fe is not None and not isinstance(fe, list):
                    issues.append("Field 'field_evidence' in explainability must be a list.")
                elif isinstance(fe, list):
                    code_evidence = str(asset.get("evidence") or "")
                    for item in fe:
                        if not isinstance(item, dict):
                            issues.append("Each item in field_evidence must be a dictionary.")
                            continue
                        etype = item.get("evidence_type")
                        if etype and etype not in self.ALLOWED_EVIDENCE_TYPES:
                            issues.append(f"Invalid evidence_type '{etype}'.")
                        src = item.get("source")
                        snp = str(item.get("snippet") or "")
                        if src in ("source_code", "provided_source_code") and code_evidence and snp:
                            if snp not in code_evidence and not any(part in code_evidence for part in snp.split()):
                                issues.append(f"Evidence snippet '{snp}' not found in source code evidence.")

        # Extract fields for consistency check without mutating original values
        algorithm = str(asset.get("algorithm") or "").upper()
        family = str(asset.get("family") or "").lower()
        parameters = asset.get("parameters") or {}
        if not isinstance(parameters, dict):
            parameters = {}

        is_contradictory = False

        # 2. Algorithm vs Family Consistency Check
        for known_alg, expected_family in self.KNOWN_FAMILIES.items():
            if known_alg in algorithm:
                if family not in ("unknown", expected_family):
                    issues.append(
                        f"Algorithm '{algorithm}' conflicts with family '{family}' (expected '{expected_family}')."
                    )
                    is_contradictory = True
                break

        # 3. Parameter Patterns Check
        if family == "hash" or any(h in algorithm for h in ["SHA", "MD5", "HASH"]):
            if parameters.get("mode"):
                issues.append(
                    f"Hash algorithm '{algorithm}' cannot have encryption mode '{parameters.get('mode')}'."
                )
                is_contradictory = True

        if "RSA" in algorithm or family == "asymmetric":
            key_size = parameters.get("key_size")
            if key_size is not None:
                if not isinstance(key_size, int) or key_size <= 0:
                    issues.append(
                        f"Invalid non-integer key_size '{key_size}' for asymmetric algorithm '{algorithm}'."
                    )
                    is_contradictory = True

        if "AES" in algorithm or family == "symmetric":
            mode = parameters.get("mode")
            if mode is not None and str(mode).upper() not in self.VALID_AES_MODES:
                issues.append(
                    f"Unrecognized cipher mode '{mode}' for symmetric algorithm '{algorithm}'."
                )
                is_contradictory = True

        # 4. Assign Status based on findings
        if is_contradictory:
            status = "needs_review"
        else:
            has_algorithm = bool(algorithm and algorithm != "UNKNOWN")
            has_family = bool(family and family != "unknown")
            has_evidence = bool(asset.get("evidence"))

            has_required_params = True
            if "RSA" in algorithm:
                has_required_params = bool(parameters.get("key_size"))
            elif "AES" in algorithm:
                has_required_params = bool(
                    parameters.get("mode") or parameters.get("key_size")
                )

            if has_algorithm and has_family and has_evidence and has_required_params:
                status = "confirmed"
            else:
                status = "partial"

        asset["validation_status"] = status
        return asset

    def validate(self, cbom_json: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validates the entire CBOM document and all embedded crypto_assets.

        :param cbom_json: Full CBOM dictionary object.
        :return: Tuple (is_valid: bool, list_of_error_strings)
        """
        errors = []

        if not isinstance(cbom_json, dict):
            return False, ["CBOM output must be a JSON object (dictionary)."]

        if "format" not in cbom_json:
            errors.append("Missing required field: 'format'.")

        if "version" not in cbom_json:
            errors.append("Missing required field: 'version'.")

        if "generated_at" not in cbom_json:
            errors.append("Missing required field: 'generated_at'.")

        if "repository" not in cbom_json or not isinstance(cbom_json["repository"], dict):
            errors.append("Missing or invalid field: 'repository' must be a dictionary.")

        if "summary" not in cbom_json or not isinstance(cbom_json["summary"], dict):
            errors.append("Missing or invalid field: 'summary' must be a dictionary.")

        if "crypto_assets" not in cbom_json or not isinstance(cbom_json["crypto_assets"], list):
            errors.append("Missing or invalid field: 'crypto_assets' must be a list.")
        else:
            for idx, asset in enumerate(cbom_json["crypto_assets"]):
                if not isinstance(asset, dict):
                    errors.append(f"Asset at index {idx} must be a dictionary.")
                    continue

                for field in self.REQUIRED_ASSET_FIELDS:
                    if field not in asset:
                        errors.append(
                            f"Asset at index {idx} missing required field '{field}'."
                        )

                self.validate_asset(asset)

        is_valid = len(errors) == 0
        return is_valid, errors
