"""
CBOM Validator Component (validator.py)

Validates candidate cryptographic assets and full CycloneDX 1.6 / ECDAT CBOM documents for:
1. Structural completeness (asset_id, location, bomFormat, specVersion)
2. Cryptographic parameter sanity (AES key sizes, RSA bit lengths, ECC curves, cipher modes, padding)
3. Algorithm/family logical consistency
4. Evidence and provenance attribution integrity

Assigns explicit validation statuses:
- 'confirmed': Complete, evidence-backed, and logically consistent.
- 'partial': Valid and consistent, but missing optional parameters or code snippets.
- 'needs_review': Contradictory, inconsistent, or invalid parameter patterns detected.
- 'invalid': Structurally incomplete (missing asset_id or location file).
"""

from typing import Dict, Any, Tuple, List
from .crypto_catalog import lookup_crypto_algorithm


class CBOMValidator:
    """
    Validates cryptographic assets and CycloneDX CBOM documents for structural
    and cryptographic sanity.
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
        "ED448": "asymmetric",
        "X25519": "asymmetric",
        "X448": "asymmetric",
        "DSA": "asymmetric",
        "DH": "asymmetric",
        "AES": "symmetric",
        "AES-GCM": "symmetric",
        "AES-CBC": "symmetric",
        "AES-128": "symmetric",
        "AES-192": "symmetric",
        "AES-256": "symmetric",
        "DES": "symmetric",
        "3DES": "symmetric",
        "CHACHA20": "symmetric",
        "CHACHA20-POLY1305": "symmetric",
        "BLOWFISH": "symmetric",
        "CAMELLIA": "symmetric",
        "ARIA": "symmetric",
        "SEED": "symmetric",
        "RC4": "symmetric",
        "SHA-256": "hash",
        "SHA-512": "hash",
        "SHA-384": "hash",
        "SHA-224": "hash",
        "SHA-1": "hash",
        "SHA-3": "hash",
        "SHA3-256": "hash",
        "SHA3-512": "hash",
        "MD5": "hash",
        "HMAC": "symmetric",
        "HMAC-SHA256": "symmetric",
        "HMAC-SHA512": "symmetric",
        "HKDF": "symmetric",
        "ML-KEM": "pqc",
        "ML-KEM-512": "pqc",
        "ML-KEM-768": "pqc",
        "ML-KEM-1024": "pqc",
        "ML-DSA": "pqc",
        "ML-DSA-44": "pqc",
        "ML-DSA-65": "pqc",
        "ML-DSA-87": "pqc",
        "SLH-DSA": "pqc",
        "TLS": "protocol",
        "SSL": "protocol",
        "OPENSSL TLS": "protocol",
        "SSH": "protocol",
        "IPSEC": "protocol",
    }

    VALID_AES_MODES = {"GCM", "CBC", "CTR", "ECB", "CFB", "OFB", "CCM", "XTS"}
    VALID_AES_KEY_SIZES = {128, 192, 256}
    VALID_RSA_KEY_SIZES = {1024, 2048, 3072, 4096, 8192}
    VALID_CURVES = {"P-256", "P-384", "P-521", "P-224", "ED25519", "ED448", "X25519", "X448", "SECP256R1", "PRIME256V1"}

    def validate_asset(self, asset: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validates a single candidate cryptographic asset without mutating its evidence.
        Determines and sets asset['validation_status'] and appends explicit validation notes.

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
            asset["validation_issues"] = issues
            return asset

        # Validate explainability structure if present
        exp = asset.get("explainability")
        if isinstance(exp, dict):
            field_evidence = exp.get("field_evidence") or []
            if isinstance(field_evidence, list):
                for item in field_evidence:
                    if isinstance(item, dict):
                        ev_type = item.get("evidence_type")
                        if ev_type and ev_type not in self.ALLOWED_EVIDENCE_TYPES:
                            issues.append(f"Invalid evidence_type: {ev_type}")

        # 2. Cryptographic Parameter Sanity Checks
        algo_raw = str(asset.get("algorithm") or "").upper().strip()
        family = str(asset.get("family") or "").lower().strip()
        params = asset.get("parameters", {}) if isinstance(asset.get("parameters"), dict) else {}
        key_size = params.get("key_size") or asset.get("key_size")
        mode = params.get("mode") or asset.get("mode")
        curve = params.get("curve") or asset.get("curve")
        padding = params.get("padding") or asset.get("padding")

        # Family logical consistency check
        for known_prefix, expected_fam in self.KNOWN_FAMILIES.items():
            if algo_raw.startswith(known_prefix) and family not in (expected_fam, "pqc", "other"):
                issues.append(f"Algorithm {algo_raw} is normally {expected_fam}, but labeled as {family}.")
                break

        # AES checks
        if "AES" in algo_raw:
            if key_size is not None and key_size not in self.VALID_AES_KEY_SIZES:
                issues.append(f"Invalid AES key size: {key_size} (must be 128, 192, or 256 bits).")
            if mode and mode.upper() not in self.VALID_AES_MODES:
                issues.append(f"Invalid AES mode: {mode}.")

        # RSA checks
        if "RSA" in algo_raw:
            if mode:
                issues.append(f"Cipher mode {mode} is not applicable to asymmetric RSA.")
            if key_size is not None:
                if key_size < 1024:
                    issues.append(f"RSA key size {key_size} is insecure and deprecated (minimum 1024, recommended 2048+).")
                elif key_size not in self.VALID_RSA_KEY_SIZES:
                    issues.append(f"Non-standard RSA key size: {key_size}.")

        # ECC checks
        if any(ecc in algo_raw for ecc in ["ECDSA", "ECDH", "ECC", "ED25519"]):
            if mode:
                issues.append(f"Cipher mode {mode} is not applicable to elliptic curve cryptography.")
            if curve and curve.upper() not in self.VALID_CURVES:
                issues.append(f"Unrecognized or unsupported elliptic curve: {curve}.")

        # Mode on Hash check
        if family == "hash" and mode:
            issues.append(f"Cipher mode {mode} cannot be applied to cryptographic hash functions.")

        # 3. Validation Status Assignment
        has_critical_error = any("Invalid" in iss or "insecure" in iss for iss in issues)
        has_warning = len(issues) > 0

        if has_critical_error:
            asset["validation_status"] = "needs_review"
        elif has_warning:
            asset["validation_status"] = "needs_review"
        else:
            # Check completeness for confirmed vs partial
            is_complete = bool(asset.get("algorithm") and asset.get("family") and asset.get("evidence"))
            if family in ("asymmetric", "symmetric") and key_size is None and curve is None:
                asset["validation_status"] = "partial"
            elif is_complete:
                asset["validation_status"] = "confirmed"
            else:
                asset["validation_status"] = "partial"

        if issues:
            asset["validation_issues"] = issues

        return asset

    def validate_cyclonedx_bom(self, bom: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validates CycloneDX 1.6 root structure and components.

        :param bom: CycloneDX dictionary.
        :return: (is_valid, list_of_errors)
        """
        errors = []
        if not isinstance(bom, dict):
            return False, ["Root BOM document must be a JSON object."]

        if bom.get("bomFormat") != "CycloneDX":
            errors.append(f"Invalid bomFormat: {bom.get('bomFormat')} (expected 'CycloneDX').")

        if bom.get("specVersion") != "1.6":
            errors.append(f"Invalid specVersion: {bom.get('specVersion')} (expected '1.6').")

        if not bom.get("serialNumber") or not str(bom.get("serialNumber")).startswith("urn:uuid:"):
            errors.append("Missing or invalid serialNumber URN.")

        metadata = bom.get("metadata")
        if not isinstance(metadata, dict) or not metadata.get("timestamp"):
            errors.append("Missing metadata.timestamp.")

        components = bom.get("components")
        if not isinstance(components, list):
            errors.append("components must be a list.")
        else:
            for idx, comp in enumerate(components):
                if not isinstance(comp, dict):
                    errors.append(f"components[{idx}] is not an object.")
                    continue
                if comp.get("type") != "cryptographic-asset":
                    errors.append(f"components[{idx}].type must be 'cryptographic-asset'.")
                if not comp.get("bom-ref"):
                    errors.append(f"components[{idx}] missing 'bom-ref'.")
                if not comp.get("name"):
                    errors.append(f"components[{idx}] missing 'name'.")
                
                crypto_props = comp.get("cryptoProperties")
                if not isinstance(crypto_props, dict) or not crypto_props.get("assetType"):
                    errors.append(f"components[{idx}].cryptoProperties missing or invalid assetType.")

        return len(errors) == 0, errors

    def validate(self, cbom_doc: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Alias for validate_cbom_document for backward compatibility.
        """
        return self.validate_cbom_document(cbom_doc)

    def validate_cbom_document(self, cbom_doc: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validates full ECDAT CBOM document and embedded CycloneDX 1.6 structure.

        :param cbom_doc: CBOM document dictionary.
        :return: (is_valid, list_of_errors)
        """
        errors = []
        if not isinstance(cbom_doc, dict):
            return False, ["CBOM document must be a JSON object."]

        if cbom_doc.get("format") != "ECDAT-CBOM":
            errors.append(f"Invalid format: {cbom_doc.get('format')} (expected 'ECDAT-CBOM').")

        summary = cbom_doc.get("summary")
        if not isinstance(summary, dict):
            errors.append("Missing summary block.")
        else:
            assets = cbom_doc.get("crypto_assets", [])
            if summary.get("total_assets") != len(assets):
                errors.append(f"Summary total_assets ({summary.get('total_assets')}) does not match actual assets count ({len(assets)}).")

        # Validate embedded CycloneDX BOM if present
        if "cyclonedx_bom" in cbom_doc:
            cdx_valid, cdx_errors = self.validate_cyclonedx_bom(cbom_doc["cyclonedx_bom"])
            if not cdx_valid:
                errors.extend([f"CycloneDX: {e}" for e in cdx_errors])

        return len(errors) == 0, errors

