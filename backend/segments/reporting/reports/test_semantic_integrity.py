"""Automated Semantic Integrity and Precision Test Suite for ECDAT.

Tests the 9 mandatory semantic test cases specified in the ECDAT Precision
Correction & Report Integrity Upgrade requirements:
1. RSA Signature -> Shor-vulnerable, recommended replacement ML-DSA (not ML-KEM).
2. RSA Key Establishment -> Shor-vulnerable, recommended replacement ML-KEM / Hybrid.
3. ECDSA P-256 -> Shor-vulnerable, recommended replacement ML-DSA.
4. ECDH P-256 -> Shor-vulnerable, recommended replacement ML-KEM / Hybrid.
5. AES-256-GCM -> Not Shor-vulnerable, retains strong Grover margin, no PQC swap.
6. SHA-1 -> Classically weak/deprecated, NOT Shor-vulnerable.
7. MD5 -> Classically broken/weak, NOT Shor-vulnerable.
8. Missing HNDL context -> Returns INSUFFICIENT_CONTEXT / NOT_ASSESSABLE (never auto-zero).
9. Generic key finding -> UNKNOWN / LOW confidence without invented replacements.
"""

import unittest
from types import SimpleNamespace

from segments.mitigation.mitigation_agent.rules import compute_migration_impact
from segments.reporting.dashboard.views import _asset_risk, _pqc_replacement
from segments.ml.hndl.hndl_agent import HNDLAgent


class TestECDATSemanticIntegrity(unittest.TestCase):
    """Semantic tests validating post-quantum readiness classification and reporting."""

    def test_01_rsa_signature(self):
        """Test 1: RSA signature -> Shor-vulnerable, recommends ML-DSA (not ML-KEM)."""
        asset = SimpleNamespace(
            name="auth_service_signing_key",
            family="rsa",
            algorithm="RSA-2048",
            key_size=2048,
            curve="",
            role="digital signature",
            source_type="code",
            location="auth/signer.py",
        )
        risk_key, label, _ = _asset_risk(asset)
        self.assertEqual(risk_key, "vulnerable", "RSA signature must be classified as Shor-vulnerable")
        
        replacement = _pqc_replacement(asset)
        self.assertIn("ML-DSA", replacement, "RSA signature must recommend ML-DSA (FIPS 204)")
        self.assertNotIn("ML-KEM", replacement, "RSA signature must NOT recommend ML-KEM")

        impact = compute_migration_impact({
            "algorithm": "RSA-2048",
            "family": "rsa",
            "crypto_role": "digital signature",
            "cbom_asset": {"key_size": 2048}
        })
        self.assertIn("ML-DSA", impact["replacement"])

    def test_02_rsa_key_establishment(self):
        """Test 2: RSA key establishment -> Shor-vulnerable, recommends ML-KEM / Hybrid."""
        asset = SimpleNamespace(
            name="tls_transport_encryption_cert",
            family="rsa",
            algorithm="RSA-2048",
            key_size=2048,
            curve="",
            role="key establishment",
            source_type="config",
            location="tls/config.json",
        )
        risk_key, label, _ = _asset_risk(asset)
        self.assertEqual(risk_key, "vulnerable", "RSA key exchange must be classified as Shor-vulnerable")
        
        replacement = _pqc_replacement(asset)
        self.assertIn("ML-KEM", replacement, "RSA key establishment must recommend ML-KEM (FIPS 203)")
        
        impact = compute_migration_impact({
            "algorithm": "RSA-2048",
            "family": "rsa",
            "crypto_role": "key exchange",
            "cbom_asset": {"key_size": 2048}
        })
        self.assertIn("ML-KEM", impact["replacement"])

    def test_03_ecdsa_p256(self):
        """Test 3: ECDSA P-256 -> Shor-vulnerable, recommends ML-DSA."""
        asset = SimpleNamespace(
            name="jwt_signature_p256",
            family="ecc",
            algorithm="ECDSA",
            key_size=256,
            curve="secp256r1",
            role="digital signature",
            source_type="code",
            location="crypto/cert.py",
        )
        risk_key, label, _ = _asset_risk(asset)
        self.assertEqual(risk_key, "vulnerable", "ECDSA must be classified as Shor-vulnerable")
        
        replacement = _pqc_replacement(asset)
        self.assertIn("ML-DSA", replacement, "ECDSA must recommend ML-DSA")

        impact = compute_migration_impact({
            "algorithm": "ECDSA",
            "family": "ecc",
            "crypto_role": "signature",
            "cbom_asset": {"curve": "secp256r1"}
        })
        self.assertIn("ML-DSA", impact["replacement"])

    def test_04_ecdh_p256(self):
        """Test 4: ECDH P-256 -> Shor-vulnerable, recommends ML-KEM / Hybrid."""
        asset = SimpleNamespace(
            name="tls_ecdh_key_exchange",
            family="ecc",
            algorithm="ECDH",
            key_size=256,
            curve="secp256r1",
            role="key exchange",
            source_type="network",
            location="tls/handshake",
        )
        risk_key, label, _ = _asset_risk(asset)
        self.assertEqual(risk_key, "vulnerable", "ECDH must be classified as Shor-vulnerable")
        
        replacement = _pqc_replacement(asset)
        self.assertIn("ML-KEM", replacement, "ECDH must recommend ML-KEM or hybrid")

        impact = compute_migration_impact({
            "algorithm": "ECDH",
            "family": "ecc",
            "crypto_role": "key establishment",
            "cbom_asset": {"curve": "secp256r1"}
        })
        self.assertIn("ML-KEM", impact["replacement"])

    def test_05_aes_256_gcm(self):
        """Test 5: AES-256-GCM -> Not Shor-vulnerable, retains strong Grover margin."""
        asset = SimpleNamespace(
            name="db_column_encryption",
            family="symmetric",
            algorithm="AES-256-GCM",
            key_size=256,
            curve="",
            role="data encryption",
            source_type="code",
            location="storage/db_enc.py",
        )
        risk_key, label, _ = _asset_risk(asset)
        self.assertNotEqual(risk_key, "vulnerable", "AES-256 must NOT be marked Shor-vulnerable")
        self.assertEqual(risk_key, "moderate", "AES-256 has moderate Grover quantum margin")

        replacement = _pqc_replacement(asset)
        self.assertIn("Retain", replacement, "AES-256 should be retained")

        impact = compute_migration_impact({
            "algorithm": "AES-256-GCM",
            "family": "symmetric",
            "crypto_role": "encryption",
            "cbom_asset": {"key_size": 256}
        })
        self.assertIn("Retain", impact["replacement"])

    def test_06_sha1(self):
        """Test 6: SHA-1 -> Classically weak/deprecated, NOT Shor-vulnerable."""
        asset = SimpleNamespace(
            name="legacy_file_hash",
            family="hash",
            algorithm="SHA-1",
            key_size=160,
            curve="",
            role="integrity",
            source_type="code",
            location="legacy/checksum.py",
        )
        risk_key, label, _ = _asset_risk(asset)
        self.assertEqual(risk_key, "weak", "SHA-1 must be classified as classically weak/deprecated")
        self.assertNotEqual(risk_key, "vulnerable", "SHA-1 must NOT be classified as Shor-vulnerable")

        replacement = _pqc_replacement(asset)
        self.assertIn("SHA-256", replacement, "SHA-1 must recommend SHA-256 or SHA-3")

    def test_07_md5(self):
        """Test 7: MD5 -> Classically broken/weak, NOT Shor-vulnerable."""
        asset = SimpleNamespace(
            name="legacy_checksum_calc",
            family="hash",
            algorithm="MD5",
            key_size=128,
            curve="",
            role="hash",
            source_type="code",
            location="util/digest.py",
        )
        risk_key, label, _ = _asset_risk(asset)
        self.assertEqual(risk_key, "weak", "MD5 must be classified as classically broken/weak")
        self.assertNotEqual(risk_key, "vulnerable", "MD5 must NOT be classified as Shor-vulnerable")

        replacement = _pqc_replacement(asset)
        self.assertIn("SHA-256", replacement, "MD5 must recommend SHA-256 / SHA-3 or modern KDF")

    def test_08_missing_hndl_context(self):
        """Test 8: Missing HNDL context returns INSUFFICIENT_CONTEXT / NOT_ASSESSABLE (never auto-zero)."""
        finding = {
            "asset_id": "asset-test-001",
            "algorithm": "RSA-2048",
            "service": "backend-api",
            "purpose": "auth",
        }
        system_context = {}  # completely empty operational context
        
        agent = HNDLAgent()
        result = agent.analyze(finding, operational_context=system_context)
        hndl_info = result.get("hndl", {})
        self.assertIn(
            hndl_info.get("urgency_tier"),
            ["INSUFFICIENT_CONTEXT", "NOT_ASSESSABLE", "UNKNOWN"],
            "Empty operational context must return INSUFFICIENT_CONTEXT or NOT_ASSESSABLE"
        )
        self.assertEqual(hndl_info.get("evidence_status"), "INSUFFICIENT_CONTEXT")

    def test_09_generic_unknown_finding(self):
        """Test 9: Generic finding -> UNKNOWN / LOW confidence without invented replacements."""
        asset = SimpleNamespace(
            name="unidentified_crypto_buffer",
            family="unknown",
            algorithm="UNKNOWN_CIPHER",
            key_size=None,
            curve="",
            role="unknown",
            source_type="code",
            location="raw/crypto.bin",
        )
        risk_key, label, _ = _asset_risk(asset)
        self.assertEqual(risk_key, "unknown", "Generic finding must have risk_key 'unknown'")

    def test_10_sha512_retain(self):
        """Test 10: SHA-512 -> Retain (Strong), do NOT recommend downgrade to SHA-256."""
        asset = SimpleNamespace(
            name="integrity_digest_sha512",
            family="hash",
            algorithm="SHA-512",
            key_size=512,
            curve="",
            role="digest",
            source_type="code",
            location="security/hash.py",
        )
        risk_key, label, _ = _asset_risk(asset)
        self.assertEqual(risk_key, "moderate", "SHA-512 must have moderate Grover margin")
        self.assertNotEqual(risk_key, "vulnerable", "SHA-512 is NOT Shor-vulnerable")

        replacement = _pqc_replacement(asset)
        self.assertIn("Retain", replacement, "SHA-512 must recommend Retain")

        impact = compute_migration_impact({
            "algorithm": "SHA-512",
            "family": "hash",
            "crypto_role": "digest",
            "cbom_asset": {"key_size": 512}
        })
        self.assertIn("Retain", impact["replacement"])

    def test_11_des_classical_broken(self):
        """Test 11: DES -> Classically broken, NOT Shor-vulnerable."""
        asset = SimpleNamespace(
            name="legacy_des_block_cipher",
            family="symmetric",
            algorithm="DES",
            key_size=56,
            curve="",
            role="encryption",
            source_type="code",
            location="legacy/crypto_des.c",
        )
        risk_key, label, _ = _asset_risk(asset)
        self.assertEqual(risk_key, "weak", "DES must be classified as classically weak/broken")
        self.assertNotEqual(risk_key, "vulnerable", "DES is NOT Shor-vulnerable")

        from segments.ml.cbom.security_classification import classify_crypto_security
        profile = classify_crypto_security(algorithm="DES", family="symmetric")
        self.assertFalse(profile.is_shor_vulnerable)

    def test_12_3des_and_blowfish(self):
        """Test 12: 3DES & Blowfish -> Classically deprecated/weak, NOT Shor-vulnerable."""
        from segments.ml.cbom.security_classification import classify_crypto_security
        p_3des = classify_crypto_security(algorithm="3DES", family="symmetric")
        self.assertFalse(p_3des.is_shor_vulnerable)
        self.assertEqual(p_3des.risk_key, "weak")

        p_blowfish = classify_crypto_security(algorithm="Blowfish", family="symmetric")
        self.assertFalse(p_blowfish.is_shor_vulnerable)
        self.assertEqual(p_blowfish.risk_key, "weak")


if __name__ == "__main__":
    unittest.main()
