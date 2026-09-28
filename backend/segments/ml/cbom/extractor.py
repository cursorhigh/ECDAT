"""
Deterministic Extractor Component for CBOM (extractor.py)

Extracts cryptographic properties (algorithm, family, asset_type, key_size, mode, curve, padding,
hash, protocol, library, crypto_role, and functions) from discovery findings and code evidence snippets
using rule-based pattern matching and the deterministic NIST/FIPS crypto catalog.
"""

import re
from typing import Dict, Any, Optional, List, Tuple

from .crypto_catalog import (
    lookup_crypto_algorithm,
    canonicalize_algorithm_name,
)


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
                r"\b(ECDSA|ECDH|ECC|ED25519|ED448|X25519|X448|DSA|DH|Diffie-Hellman|ElGamal)\b",
                re.IGNORECASE,
            ),
            "asymmetric",
            "ASYM_PATTERN_02",
        ),
        (
            re.compile(
                r"\b(ML-KEM|ML-DSA|SLH-DSA|Kyber|Dilithium|SPHINCS\+?|Falcon|BIKE|HQC)\b",
                re.IGNORECASE,
            ),
            "pqc",
            "PQC_PATTERN_01",
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
                r"\b(DES|3DES|TDES|ChaCha20|Blowfish|Twofish|Camellia|ARIA|SEED|RC4|IDEA)\b",
                re.IGNORECASE,
            ),
            "symmetric",
            "SYM_PATTERN_02",
        ),
        (
            re.compile(
                r"\b(SHA-?256|SHA-?512|SHA-?384|SHA-?224|SHA-?1|SHA-?3|MD5|RIPEMD|BLAKE2b?|BLAKE3|SHAKE128|SHAKE256)\b",
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
                r"\b(HMAC|CMAC|GMAC|KMAC|Poly1305)\b",
                re.IGNORECASE,
            ),
            "symmetric",
            "MAC_PATTERN_01",
        ),
        (
            re.compile(
                r"\b(HKDF|PBKDF2|Scrypt|Argon2)\b",
                re.IGNORECASE,
            ),
            "symmetric",
            "KDF_PATTERN_01",
        ),
    ]

    # Key size extraction patterns (explicit key size assignments only)
    KEY_SIZE_PATTERNS = [
        re.compile(r"key_size\s*=\s*(\d+)", re.IGNORECASE),
        re.compile(r"keysize\s*=\s*(\d+)", re.IGNORECASE),
        re.compile(r"key_length\s*=\s*(\d+)", re.IGNORECASE),
        re.compile(r"key_bits\s*=\s*(\d+)", re.IGNORECASE),
        re.compile(r"generate_key\((\d+)\)", re.IGNORECASE),
        re.compile(r"generate_private_key\(.*?key_size\s*=\s*(\d+)", re.IGNORECASE | re.DOTALL),
    ]

    # Mode extraction patterns
    MODE_PATTERNS = [
        re.compile(r"modes\.(GCM|CBC|CTR|ECB|CFB|OFB|CCM|XTS)", re.IGNORECASE),
        re.compile(r"MODE_(GCM|CBC|CTR|ECB|CFB|OFB|CCM|XTS)", re.IGNORECASE),
        re.compile(r"AES-(?:128|192|256)-(GCM|CBC|CTR|ECB|CFB|OFB|CCM|XTS)", re.IGNORECASE),
        re.compile(r"\b(GCM|CBC|CTR|ECB|CFB|OFB|CCM|XTS)\b", re.IGNORECASE),
    ]

    # Padding extraction patterns
    PADDING_PATTERNS = [
        re.compile(r"padding\.(OAEP|PSS|PKCS1v15|PKCS7)", re.IGNORECASE),
        re.compile(r"PKCS1_(OAEP|PSS|v1_5)", re.IGNORECASE),
        re.compile(r"\b(OAEP|PSS|PKCS1v1\.5|PKCS1v15|PKCS#1|PKCS7)\b", re.IGNORECASE),
    ]

    # Curve extraction patterns
    CURVE_PATTERNS = [
        re.compile(r"\b(SECP256R1|prime256v1|P-256|P256)\b", re.IGNORECASE),
        re.compile(r"\b(SECP384R1|P-384|P384)\b", re.IGNORECASE),
        re.compile(r"\b(SECP521R1|P-521|P521)\b", re.IGNORECASE),
        re.compile(r"\b(SECP224R1|P-224|P224)\b", re.IGNORECASE),
        re.compile(r"\b(ED25519|Ed25519)\b", re.IGNORECASE),
        re.compile(r"\b(ED448|Ed448)\b", re.IGNORECASE),
        re.compile(r"\b(X25519|Curve25519)\b", re.IGNORECASE),
        re.compile(r"\b(X448|Curve448)\b", re.IGNORECASE),
    ]

    # Protocol extraction patterns
    PROTOCOL_PATTERNS = [
        re.compile(r"\b(TLS\s*(?:v?1\.3|v?1\.2|v?1\.1|v?1\.0))\b", re.IGNORECASE),
        re.compile(r"\b(PROTOCOL_TLS_CLIENT|PROTOCOL_TLS_SERVER|PROTOCOL_TLSv1_2|PROTOCOL_TLSv1_3)\b", re.IGNORECASE),
        re.compile(r"\b(SSH\s*(?:v?2\.0|v?2))\b", re.IGNORECASE),
        re.compile(r"\b(IPsec|IKEv2|HTTPS|SFTP|QUIC|S/MIME|X\.509|PKI)\b", re.IGNORECASE),
    ]

    # Library extraction patterns
    LIBRARY_PATTERNS = [
        re.compile(r"\b(cryptography(?:\.hazmat)?)\b", re.IGNORECASE),
        re.compile(r"\b(pycryptodome|Crypto\.)\b", re.IGNORECASE),
        re.compile(r"\b(OpenSSL|libssl|libcrypto)\b", re.IGNORECASE),
        re.compile(r"\b(BoringSSL)\b", re.IGNORECASE),
        re.compile(r"\b(libsodium|sodium)\b", re.IGNORECASE),
        re.compile(r"\b(BouncyCastle|org\.bouncycastle)\b", re.IGNORECASE),
        re.compile(r"\b(Windows CNG|Bcrypt\.dll|NCrypt)\b", re.IGNORECASE),
        re.compile(r"\b(hashlib|ssl|hmac)\b", re.IGNORECASE),
    ]

    def extract(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deterministically extracts and enriches cryptographic metadata for a finding,
        populating standard cryptographic properties, catalog references, and explainability evidence.

        :param finding: Raw finding dictionary from Discovery JSON.
        :return: Extracted dictionary containing properties and explainability.
        """
        detected = str(finding.get("detected") or finding.get("algorithm") or "")
        code = str(finding.get("code") or finding.get("evidence") or "")
        file_path = str(finding.get("file") or "")
        combined_text = f"{detected} {code} {file_path}"

        # 1. Family & Asset Type Extraction
        explicit_family = finding.get("family") or finding.get("category")
        matched_rule = None

        if explicit_family:
            family = str(explicit_family).lower()
        else:
            family, matched_rule = self._infer_family_with_rule(combined_text)

        explicit_asset_type = finding.get("asset_type") or finding.get("type")
        if explicit_asset_type:
            asset_type = str(explicit_asset_type).lower()
        else:
            asset_type = self._infer_asset_type(family, detected, combined_text)

        # 2. Key Size Extraction
        params = finding.get("parameters", {}) if isinstance(finding.get("parameters"), dict) else {}
        explicit_key_size = params.get("key_size") or finding.get("key_size")
        if explicit_key_size is not None:
            try:
                key_size = int(explicit_key_size)
            except (ValueError, TypeError):
                key_size = None
        else:
            key_size = self._extract_key_size(combined_text, family, detected)

        # 3. Curve Extraction
        explicit_curve = params.get("curve") or finding.get("curve")
        if explicit_curve:
            curve = self._normalize_curve(str(explicit_curve))
        else:
            curve = self._extract_curve(combined_text)

        # 4. Mode Extraction
        explicit_mode = params.get("mode") or finding.get("mode")
        if explicit_mode:
            mode = str(explicit_mode).upper()
        else:
            mode = self._extract_mode(combined_text)

        # 5. Padding Extraction
        explicit_padding = params.get("padding") or finding.get("padding")
        if explicit_padding:
            padding = str(explicit_padding)
        else:
            padding = self._extract_padding(combined_text)

        # 6. Hash Algorithm Extraction
        explicit_hash = params.get("hash") or finding.get("hash")
        if explicit_hash:
            hash_alg = str(explicit_hash).upper()
        else:
            hash_alg = self._extract_hash(combined_text)

        # 7. Protocol & Library Extraction
        protocol = finding.get("protocol") or self._extract_protocol(combined_text)
        crypto_library = finding.get("crypto_library") or finding.get("library") or self._extract_library(combined_text)

        # 8. Canonical Algorithm Resolution & Knowledge Catalog Lookup
        algorithm_name = self._resolve_algorithm_name(detected, key_size, curve, mode, hash_alg, family)
        catalog_entry = lookup_crypto_algorithm(algorithm_name, key_size=key_size, curve=curve, mode=mode)

        if catalog_entry:
            canonical_algo = catalog_entry["canonical_name"]
            if family in ("unknown", None, ""):
                family = catalog_entry["family"]
            primitive = catalog_entry["primitive"]
            crypto_role = catalog_entry["crypto_role"]
            crypto_functions = catalog_entry["crypto_functions"]
            classical_security_bits = catalog_entry["classical_security_bits_est"]
            nist_quantum_level = catalog_entry["nist_security_category"]
            quantum_vulnerable = catalog_entry["quantum_vulnerable"]
            quantum_attack_type = catalog_entry["quantum_attack_type"]
            deprecated_or_disallowed = catalog_entry["deprecated_or_disallowed"]
            oid = catalog_entry["oid"]
            # Only key-bearing cryptographic families may populate key_size from catalog
            if key_size is None and catalog_entry.get("key_or_hash_size_bits"):
                cat_fam = str(catalog_entry.get("family", "")).lower()
                cat_role = str(catalog_entry.get("crypto_role", "")).lower()
                if cat_fam in ("asymmetric", "symmetric", "rsa", "dsa", "dh", "ecc", "aes", "des", "3des", "des3") and cat_role not in ("hash", "mac", "message_digest"):
                    key_size = catalog_entry["key_or_hash_size_bits"]
            if curve is None and catalog_entry.get("curve"):
                curve = catalog_entry["curve"]
        else:
            canonical_algo = canonicalize_algorithm_name(algorithm_name, key_size=key_size, curve=curve)
            primitive = family
            crypto_role = "encryption" if family == "symmetric" else ("signature" if family == "asymmetric" else "hash")
            crypto_functions = ["encrypt", "decrypt"] if family == "symmetric" else (["sign", "verify"] if family == "asymmetric" else ["digest"])
            classical_security_bits = key_size if key_size else None
            nist_quantum_level = 0 if family == "asymmetric" else (5 if (key_size and key_size >= 256) else 1)
            quantum_vulnerable = True if family == "asymmetric" else False
            quantum_attack_type = "Shor" if family == "asymmetric" else "Grover"
            deprecated_or_disallowed = False
            oid = None

        # 9. Purpose & Implementation
        purpose = finding.get("purpose") or self._infer_purpose(family, crypto_role, detected, combined_text)
        implementation = finding.get("implementation") or self._extract_implementation_symbol(code, crypto_library)

        # 10. Confidence Determination
        confidence = self._compute_confidence(finding, canonical_algo, key_size, mode, curve)

        return {
            "algorithm": canonical_algo,
            "family": family,
            "asset_type": asset_type,
            "key_size": key_size,
            "mode": mode,
            "curve": curve,
            "padding": padding,
            "hash": hash_alg,
            "protocol": protocol,
            "crypto_library": crypto_library,
            "purpose": purpose,
            "implementation": implementation,
            "primitive": primitive,
            "crypto_role": crypto_role,
            "crypto_functions": crypto_functions,
            "classical_security_bits": classical_security_bits,
            "nist_quantum_level": nist_quantum_level,
            "quantum_vulnerable": quantum_vulnerable,
            "quantum_attack_type": quantum_attack_type,
            "deprecated_or_disallowed": deprecated_or_disallowed,
            "oid": oid,
            "confidence": confidence,
            "detection_method": "deterministic",
            "matched_rule": matched_rule,
        }

    def _infer_family_with_rule(self, text: str) -> Tuple[str, Optional[str]]:
        for pattern, family_name, rule_id in self.FAMILY_PATTERNS:
            if pattern.search(text):
                return family_name, rule_id
        return "other", None

    def _infer_asset_type(self, family: str, detected: str, text: str) -> str:
        if family == "protocol" or any(p in detected.lower() for p in ["tls", "ssl", "ssh", "ipsec", "https"]):
            return "protocol"
        if "cert" in detected.lower() or "x509" in text.lower() or "certificate" in text.lower():
            return "certificate"
        return "algorithm"

    def _extract_key_size(self, text: str, family: str, detected: str) -> Optional[int]:
        fam_lower = (family or "").lower()
        det_lower = (detected or "").lower().replace("-", "").replace("_", "").replace(" ", "")

        # Hashes, MACs, protocols, and indicators NEVER carry key_size
        hash_prefixes = ("sha", "md5", "md4", "md2", "ripemd", "blake", "shake", "hash", "tls", "ssl", "crypto")
        if fam_lower in ("hash", "mac", "protocol") or any(det_lower.startswith(h) for h in hash_prefixes):
            return None
        if det_lower in ("crypto", "key", "tls", "hash", "cipher", "openssl", "certificate"):
            return None

        # Check explicit detection name for key algorithms only (e.g. "AES-256", "RSA-4096")
        if any(k in det_lower for k in ("rsa", "aes", "des", "3des", "mlkem", "mldsa")):
            name_match = re.search(r"-(1024|2048|3072|4096|8192|128|192|256)\b", detected)
            if name_match:
                return int(name_match.group(1))

        # Check explicit code context
        for pat in self.KEY_SIZE_PATTERNS:
            m = pat.search(text)
            if m:
                try:
                    val = int(m.group(1))
                    if val in (1024, 2048, 3072, 4096, 8192, 128, 192, 256, 384, 512, 521, 224, 160):
                        return val
                except (ValueError, IndexError):
                    continue

        return None

    def _extract_mode(self, text: str) -> Optional[str]:
        for pat in self.MODE_PATTERNS:
            m = pat.search(text)
            if m:
                mode_cand = m.group(1).upper()
                if mode_cand in ("GCM", "CBC", "CTR", "ECB", "CFB", "OFB", "CCM", "XTS"):
                    return mode_cand
        return None

    def _extract_padding(self, text: str) -> Optional[str]:
        for pat in self.PADDING_PATTERNS:
            m = pat.search(text)
            if m:
                raw_pad = m.group(1).upper()
                if "OAEP" in raw_pad:
                    return "OAEP"
                if "PSS" in raw_pad:
                    return "PSS"
                if "PKCS1" in raw_pad:
                    return "PKCS1v1.5"
                if "PKCS7" in raw_pad:
                    return "PKCS7"
                return raw_pad
        return None

    def _extract_curve(self, text: str) -> Optional[str]:
        for pat in self.CURVE_PATTERNS:
            m = pat.search(text)
            if m:
                return m.group(1)
        return None

    def _normalize_curve(self, curve_raw: str) -> str:
        c = curve_raw.strip().upper()
        if "256R1" in c or "PRIME256V1" in c or c in ("P-256", "P256"):
            return "P-256"
        if "384R1" in c or c in ("P-384", "P384"):
            return "P-384"
        if "521R1" in c or c in ("P-521", "P521"):
            return "P-521"
        if "224R1" in c or c in ("P-224", "P224"):
            return "P-224"
        if "ED25519" in c:
            return "Ed25519"
        if "ED448" in c:
            return "Ed448"
        if "X25519" in c or "CURVE25519" in c:
            return "X25519"
        if "X448" in c or "CURVE448" in c:
            return "X448"
        return curve_raw.strip()

    def _extract_hash(self, text: str) -> Optional[str]:
        m = re.search(r"\b(SHA-?256|SHA-?512|SHA-?384|SHA-?224|SHA-?1|SHA-?3-?256|SHA-?3-?512|MD5|BLAKE2b|BLAKE3)\b", text, re.IGNORECASE)
        if m:
            raw = m.group(1).upper().replace("_", "-")
            if "SHA256" in raw or "SHA-256" in raw:
                return "SHA-256"
            if "SHA512" in raw or "SHA-512" in raw:
                return "SHA-512"
            if "SHA384" in raw or "SHA-384" in raw:
                return "SHA-384"
            if "SHA1" in raw or "SHA-1" in raw:
                return "SHA-1"
            if "MD5" in raw:
                return "MD5"
            return raw
        return None

    def _extract_protocol(self, text: str) -> Optional[str]:
        for pat in self.PROTOCOL_PATTERNS:
            m = pat.search(text)
            if m:
                raw_proto = m.group(1).strip()
                if "1.3" in raw_proto or "TLSv1_3" in raw_proto:
                    return "TLS 1.3"
                if "1.2" in raw_proto or "TLSv1_2" in raw_proto:
                    return "TLS 1.2"
                if "TLS" in raw_proto.upper() or "SSL" in raw_proto.upper():
                    return "TLS 1.2"
                if "SSH" in raw_proto.upper():
                    return "SSH 2.0"
                if "IPSEC" in raw_proto.upper() or "IKE" in raw_proto.upper():
                    return "IPsec"
                return raw_proto
        return None

    def _extract_library(self, text: str) -> Optional[str]:
        for pat in self.LIBRARY_PATTERNS:
            m = pat.search(text)
            if m:
                raw_lib = m.group(1)
                if "cryptography" in raw_lib.lower():
                    return "cryptography (Python)"
                if "pycryptodome" in raw_lib.lower() or "crypto." in raw_lib.lower():
                    return "PyCryptodome"
                if "openssl" in raw_lib.lower() or "libssl" in raw_lib.lower():
                    return "OpenSSL"
                if "boringssl" in raw_lib.lower():
                    return "BoringSSL"
                if "sodium" in raw_lib.lower():
                    return "libsodium"
                if "bouncycastle" in raw_lib.lower():
                    return "BouncyCastle"
                if "bcrypt" in raw_lib.lower() or "cng" in raw_lib.lower():
                    return "Windows CNG"
                if "hashlib" in raw_lib.lower() or "ssl" in raw_lib.lower():
                    return "Python Standard Library"
                return raw_lib
        return None

    def _resolve_algorithm_name(
        self,
        detected: str,
        key_size: Optional[int],
        curve: Optional[str],
        mode: Optional[str],
        hash_alg: Optional[str],
        family: str,
    ) -> str:
        d = detected.strip()
        if not d or d.lower() in ("customcryptoref", "unknown", "crypto"):
            if family == "asymmetric":
                if curve:
                    return f"ECDSA-{curve}"
                return f"RSA-{key_size or 2048}"
            if family == "symmetric":
                return f"AES-{key_size or 256}"
            if family == "hash":
                return hash_alg or "SHA-256"
            return "Unknown-Algorithm"

        # If detected is plain AES and mode is GCM -> AES-GCM or AES-256
        if d.upper() == "AES" and key_size:
            return f"AES-{key_size}"
        if d.upper() == "RSA" and key_size:
            return f"RSA-{key_size}"
        if d.upper() == "ECDSA" and curve:
            return f"ECDSA-{curve}"
        if d.upper() == "ECDH" and curve:
            return f"ECDH-{curve}"

        return d

    def _infer_purpose(self, family: str, role: str, detected: str, text: str) -> str:
        if "auth" in text.lower() or "sign" in text.lower() or "token" in text.lower():
            return "authentication_and_signing"
        if "session" in text.lower() or "network" in text.lower() or "tls" in text.lower():
            return "transport_encryption"
        if "hash" in text.lower() or "digest" in text.lower():
            return "integrity_verification"
        if "kdf" in text.lower() or "derive" in text.lower():
            return "key_derivation"
        if role == "signature":
            return "digital_signature"
        if role == "key_establishment":
            return "key_agreement"
        if role in ("encryption", "AEAD"):
            return "data_encryption"
        return "general_cryptographic_operation"

    def _extract_implementation_symbol(self, code: str, library: Optional[str]) -> Optional[str]:
        if not code:
            return library
        m = re.search(r"([a-zA-Z0-9_\.]+\([^\)]*\))", code)
        if m:
            return m.group(1)[:120]
        return library

    def _compute_confidence(
        self,
        finding: Dict[str, Any],
        algorithm: str,
        key_size: Optional[int],
        mode: Optional[str],
        curve: Optional[str],
    ) -> float:
        explicit_conf = finding.get("confidence")
        if explicit_conf is not None:
            try:
                return round(float(explicit_conf), 2)
            except (ValueError, TypeError):
                pass

        if algorithm.lower() == "unknown-algorithm":
            return 0.30

        score = 0.80
        code = str(finding.get("code") or "")
        if code:
            score += 0.10
        if key_size is not None or curve is not None or mode is not None:
            score += 0.05

        return min(round(score, 2), 0.99)
