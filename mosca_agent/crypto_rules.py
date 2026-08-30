"""
MOSCA+ Deterministic Cryptographic Rule Engine

Extracts known cryptographic facts (algorithm category, quantum attack type,
quantum vulnerability flag, classical security baseline) prior to AI contextual analysis.
"""

import re
from typing import Dict, Any, Optional, Tuple, List


class CryptoRuleEngine:
    """
    Deterministic rule-based analyzer for cryptographic algorithms and key sizes.
    """

    PUBLIC_KEY_PATTERNS = [
        r"\bRSA\b", r"\bECC\b", r"\bECDSA\b", r"\bECDH\b", r"\bDSA\b",
        r"\bDH\b", r"\bDIFFIE-HELLMAN\b", r"\bED25519\b", r"\bX25519\b", r"\bELGAMAL\b"
    ]

    SYMMETRIC_PATTERNS = [
        r"\bAES\b", r"\bAES-GCM\b", r"\bAES-CBC\b", r"\bCHACHA20\b",
        r"\b3DES\b", r"\bTDES\b", r"\bDES\b", r"\bBLOWFISH\b", r"\bCAMELLIA\b"
    ]

    HASH_PATTERNS = [
        r"\bSHA-?256\b", r"\bSHA-?512\b", r"\bSHA-?384\b", r"\bSHA-?224\b",
        r"\bSHA-?1\b", r"\bSHA-?3\b", r"\bMD5\b", r"\bBLAKE2\b", r"\bRIPEMD\b"
    ]

    def analyze(self, asset: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyzes CBOM cryptographic asset and returns deterministic facts.

        :param asset: CBOM asset dictionary.
        :return: Deterministic findings dictionary.
        """
        algo_obj = asset.get("algorithm") or {}
        if isinstance(algo_obj, dict):
            family = str(algo_obj.get("family") or "").upper()
            name = str(algo_obj.get("name") or "").upper()
        else:
            family = str(algo_obj).upper()
            name = str(algo_obj).upper()

        combined = f"{family} {name}".strip()

        params = asset.get("parameters") or {}
        if not isinstance(params, dict):
            params = {}

        key_size = params.get("key_size")

        purpose_list = asset.get("purpose") or []
        if isinstance(purpose_list, str):
            purpose_list = [purpose_list]

        # 1. Determine Algorithm Category & Quantum Attack Type
        category, quantum_vulnerable, quantum_attack = self._classify_category(combined)

        # 2. Analyze Classical Security Baseline
        classical_baseline = self._analyze_classical_baseline(category, combined, key_size)

        # 3. Assess Purpose Context
        purpose_summary = [str(p) for p in purpose_list if p]

        confidence = "HIGH" if category != "UNKNOWN" else "LOW"

        return {
            "algorithm_category": category,
            "known_quantum_vulnerable": quantum_vulnerable,
            "quantum_attack": quantum_attack,
            "classical_baseline": classical_baseline,
            "purpose_context": purpose_summary,
            "confidence": confidence,
        }

    def _classify_category(self, text: str) -> Tuple[str, Optional[bool], str]:
        if not text or text.strip() in ("UNKNOWN", "CUSTOMCRYPTOREF", "PROPRIETARYCRYPTO"):
            return "UNKNOWN", None, "UNKNOWN"

        for pat in self.PUBLIC_KEY_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                return "PUBLIC_KEY", True, "SHOR"

        for pat in self.SYMMETRIC_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                return "SYMMETRIC", False, "GROVER"

        for pat in self.HASH_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                return "HASH", False, "GROVER"

        return "UNKNOWN", None, "UNKNOWN"

    def _analyze_classical_baseline(self, category: str, text: str, key_size: Optional[int]) -> str:
        if category == "PUBLIC_KEY":
            if "RSA" in text or "DH" in text or "DSA" in text:
                if key_size is not None:
                    if key_size <= 1024:
                        return "LEGACY_WEAK"
                    elif key_size == 2048:
                        return "ACCEPTABLE"
                    elif key_size >= 3072:
                        return "STRONG"
                return "ACCEPTABLE"
            elif any(e in text for e in ["ECC", "ECDSA", "ECDH", "25519"]):
                if key_size is not None:
                    if key_size < 256:
                        return "WEAK"
                    return "STRONG"
                return "STRONG"

        elif category == "SYMMETRIC":
            if "DES" in text and "3DES" not in text:
                return "LEGACY_WEAK"
            if key_size is not None:
                if key_size < 128:
                    return "WEAK"
                elif key_size == 128:
                    return "ACCEPTABLE"
                elif key_size >= 192:
                    return "STRONG"
            return "STRONG"

        elif category == "HASH":
            if any(w in text for w in ["MD5", "SHA-1", "SHA1"]):
                return "LEGACY_WEAK"
            return "STRONG"

        return "UNKNOWN"
