"""
Deterministic Extractor Component for CBOM

Extracts cryptographic properties (family, asset_type, key_size, mode, curve, hash, purpose, implementation)
from detected algorithm names and code evidence snippets using rule-based pattern matching,
and automatically generates evidence-based explainability details.
"""

import re
from typing import Dict, Any, Optional, List, Tuple


class DeterministicExtractor:
    """
    Deterministic rule-based extractor for cryptographic properties with evidence explainability.
    """

    # Family mapping patterns with rule names
    FAMILY_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
        (
            re.compile(
                r"\b(RSA)\b",
                re.IGNORECASE,
            ),
            "asymmetric",
            "RSA_PATTERN_01",
        ),
        (
            re.compile(
                r"\b(ECDSA|ECDH|ECC|ED25519|X25519|DSA|DH|Diffie-Hellman|ElGamal)\b",
                re.IGNORECASE,
            ),
            "asymmetric",
            "ASYM_PATTERN_02",
        ),
        (
            re.compile(
                r"\b(AES)\b",
                re.IGNORECASE,
            ),
            "symmetric",
            "AES_PATTERN_01",
        ),
        (
            re.compile(
                r"\b(DES|3DES|TDES|ChaCha20|Blowfish|RC4|Camellia|IDEA)\b",
                re.IGNORECASE,
            ),
            "symmetric",
            "SYM_PATTERN_02",
        ),
        (
            re.compile(
                r"\b(SHA-?256|SHA-?512|SHA-?384|SHA-?224|SHA-?1|SHA-?3|MD5|RIPEMD|BLAKE2b?|BLAKE3)\b",
                re.IGNORECASE,
            ),
            "hash",
            "HASH_PATTERN_01",
        ),
        (
            re.compile(
                r"\b(TLS|SSL|SSH|IPsec|HTTPS|SFTP|QUIC|OpenSSL\s+TLS)\b",
                re.IGNORECASE,
            ),
            "protocol",
            "PROTO_PATTERN_01",
        ),
        (
            re.compile(
                r"\b(HMAC|CMAC|GMAC|KMAC)\b",
                re.IGNORECASE,
            ),
            "symmetric",
            "MAC_PATTERN_01",
        ),
    ]

    def extract(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deterministically extracts and enriches cryptographic metadata for a finding,
        including rule-based field evidence and explainability output.

        :param finding: Raw finding dictionary from Discovery JSON.
        :return: Extracted dictionary containing properties and explainability.
        """
        detected = str(finding.get("detected") or finding.get("algorithm") or "")
        code = str(finding.get("code") or finding.get("evidence") or "")
        combined_text = f"{detected} {code}"

        # 1. Family & Asset Type Extraction
        explicit_family = finding.get("family") or finding.get("category")
        matched_rule = None
        matched_pat = None

        if explicit_family:
            family = explicit_family
        else:
            family, matched_rule, matched_pat = self._infer_family_with_rule(combined_text)

        explicit_asset_type = finding.get("asset_type") or finding.get("type")
        if explicit_asset_type:
            asset_type = explicit_asset_type
        elif family == "protocol":
            asset_type = "protocol"
        elif family in ["asymmetric", "symmetric", "hash"]:
            asset_type = "algorithm"
        else:
            asset_type = "algorithm" if detected and detected != "Unknown" else "unknown"

        # 2. Key Size Extraction
        key_size = finding.get("key_size")
        key_size_snippet = None
        if key_size is None:
            key_size, key_size_snippet = self._extract_key_size_with_snippet(combined_text)

        # 3. Mode Extraction
        mode = finding.get("mode")
        mode_snippet = None
        if mode is None and family == "symmetric":
            mode, mode_snippet = self._extract_mode_with_snippet(combined_text)

        # 4. Curve Extraction
        curve = finding.get("curve")
        curve_snippet = None
        if curve is None and (
            family == "asymmetric"
            or "EC" in detected.upper()
            or "EC" in code.upper()
        ):
            curve, curve_snippet = self._extract_curve_with_snippet(combined_text)

        # 5. Hash Extraction
        hash_alg = finding.get("hash")
        hash_snippet = None
        if hash_alg is None and family != "hash":
            hash_alg, hash_snippet = self._extract_hash_with_snippet(combined_text)

        # 6. Purpose & Implementation Extraction
        purpose = finding.get("purpose")
        implementation = finding.get("implementation") or finding.get("library")

        # 7. Generate Field-Level Evidence & Explainability
        field_evidence: List[Dict[str, Any]] = []
        snippet_src = code.strip() if code else detected.strip()

        if detected and detected.lower() != "unknown":
            field_evidence.append({
                "field": "algorithm",
                "value": detected,
                "source": "source_code",
                "snippet": snippet_src,
                "evidence_type": "explicit" if detected in code else "pattern_match",
                "explanation": f"The source code or scanner explicitly identifies {detected}.",
            })

        if family and family != "unknown":
            field_evidence.append({
                "field": "family",
                "value": family,
                "source": "source_code",
                "snippet": snippet_src,
                "evidence_type": "pattern_match",
                "explanation": f"Rule {matched_rule or 'DETERMINISTIC_FAMILY'} matched family '{family}'.",
            })

        if key_size is not None:
            field_evidence.append({
                "field": "parameters.key_size",
                "value": key_size,
                "source": "source_code",
                "snippet": key_size_snippet or snippet_src,
                "evidence_type": "explicit",
                "explanation": f"The parameter explicitly specifies a {key_size}-bit key.",
            })

        if mode:
            field_evidence.append({
                "field": "parameters.mode",
                "value": mode,
                "source": "source_code",
                "snippet": mode_snippet or snippet_src,
                "evidence_type": "explicit" if mode in snippet_src else "pattern_match",
                "explanation": f"Cipher mode '{mode}' detected in code evidence.",
            })

        if curve:
            field_evidence.append({
                "field": "parameters.curve",
                "value": curve,
                "source": "source_code",
                "snippet": curve_snippet or snippet_src,
                "evidence_type": "explicit",
                "explanation": f"Elliptic curve '{curve}' explicitly referenced in source code.",
            })

        if hash_alg:
            field_evidence.append({
                "field": "parameters.hash",
                "value": hash_alg,
                "source": "source_code",
                "snippet": hash_snippet or snippet_src,
                "evidence_type": "explicit",
                "explanation": f"Digest hash algorithm '{hash_alg}' detected.",
            })

        detection_reason = (
            f"The source code contains an explicit {detected or family} cryptographic API call or pattern match."
            if detected and detected != "Unknown"
            else "Deterministic rule matched cryptographic evidence pattern."
        )

        confidence_reason = (
            "High confidence because the algorithm and key parameters are explicitly present in the source code."
            if key_size or mode or detected
            else "Moderate confidence based on deterministic pattern matching."
        )

        explainability = {
            "detection_method": "deterministic",
            "detection_reason": detection_reason,
            "rule": matched_rule or "GENERIC_CRYPTO_RULE",
            "matched_pattern": matched_pat or detected,
            "evidence": field_evidence,
            "confidence_reason": confidence_reason,
            "ai_used": False,
        }

        return {
            "family": family or "unknown",
            "asset_type": asset_type or "algorithm",
            "key_size": key_size,
            "mode": mode,
            "curve": curve,
            "hash": hash_alg,
            "purpose": purpose,
            "implementation": implementation,
            "explainability": explainability,
        }

    def _infer_family_with_rule(self, text: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        for pattern, family_name, rule_id in self.FAMILY_PATTERNS:
            match = pattern.search(text)
            if match:
                return family_name, rule_id, match.group(0)
        return None, None, None

    def _extract_key_size_with_snippet(self, text: str) -> Tuple[Optional[int], Optional[str]]:
        match = re.search(
            r"(?:key_size|keysize|key_length|keylength|bit_length)\s*[:=]\s*(\d+)",
            text,
            re.IGNORECASE,
        )
        if match:
            return int(match.group(1)), match.group(0)

        match_alg = re.search(r"\b(?:AES|RSA|DSA|DH)-?(\d{3,4})\b", text, re.IGNORECASE)
        if match_alg:
            val = int(match_alg.group(1))
            if val in (128, 192, 256, 512, 1024, 2048, 3072, 4096, 8192):
                return val, match_alg.group(0)

        return None, None

    def _extract_mode_with_snippet(self, text: str) -> Tuple[Optional[str], Optional[str]]:
        match = re.search(
            r"\b(?:modes?\.)?(GCM|CBC|CTR|ECB|CFB|OFB|CCM|XTS)\b",
            text,
            re.IGNORECASE,
        )
        if match:
            return match.group(1).upper(), match.group(0)
        return None, None

    def _extract_curve_with_snippet(self, text: str) -> Tuple[Optional[str], Optional[str]]:
        match = re.search(
            r"\b(SECP256R1|SECP384R1|SECP521R1|SECP256K1|P-256|P-384|P-521|Curve25519|Ed25519|X25519)\b",
            text,
            re.IGNORECASE,
        )
        if match:
            return match.group(1), match.group(0)

        match_ec = re.search(r"ec\.(SECP\w+|P\w+|Curve\w+)", text, re.IGNORECASE)
        if match_ec:
            return match_ec.group(1), match_ec.group(0)

        return None, None

    def _extract_hash_with_snippet(self, text: str) -> Tuple[Optional[str], Optional[str]]:
        match = re.search(
            r"\b(SHA-?256|SHA-?512|SHA-?384|SHA-?224|SHA-?1|SHA-?3|MD5)\b",
            text,
            re.IGNORECASE,
        )
        if match:
            return match.group(1).upper(), match.group(0)
        return None, None
