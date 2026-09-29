"""Golden fixture test — Phase F.

Comprehensive test suite for algorithm canonicalization, classification,
normalization, and the full ECDAT pipeline. Exercises all Phase A-E changes
against a known golden fixture with exact expected classifications.

Golden fixture contents (simulated):
- RSA-2048 TLS cert → Shor-vulnerable
- P-256 ECDSA → Shor-vulnerable
- AES-256-GCM → Moderate (Grover margin)
- MD5 password hashing → Weak (Classical broken)
- SHA-1 signature → Weak (Classical deprecated)
- DES → Weak (Classical broken)
- MD5 checksum in a test file → Weak but test context (low confidence)
- "RSA" mentioned only in docs → indicator evidence only
- HMAC-SHA-1 → Legacy-Review (not weak, not strong)
"""

from django.test import TestCase

from segments.scraping.discovery.normalizer import (
    canonicalize_algorithm,
    is_bare_indicator,
    _validate_key_size,
    _infer_source_context,
    _compute_evidence_confidence,
    _guess_family_from_algorithm,
    EVIDENCE_CONFIDENCE,
)
from segments.ml.cbom.security_classification import (
    classify_crypto_security,
    ClassicalSecurityStatus,
    QuantumThreatClass,
    CryptoSecurityProfile,
)
from segments.ml.cbom.threat_context import (
    ThreatContext,
    resolve_threat_context,
    validate_analysis_invariants,
)
from segments.mitigation.mitigation_agent.rules import (
    migration_wave_for,
    compute_effort_range,
    get_standards_recommendations,
    compute_migration_impact,
    normalize_algorithm as rules_normalize_algorithm,
    WAVE_DEFS,
)


# ==========================================================================
# Phase A — Normalization & Canonicalization Tests
# ==========================================================================

class TestAlgorithmCanonicalization(TestCase):
    """A.1: Case-insensitive, separator-stripping canonicalization."""

    def test_sha1_variants(self):
        """SHA1, SHA-1, sha1, sha-1 all canonicalize to SHA-1."""
        for variant in ("SHA1", "SHA-1", "sha1", "sha-1", "Sha_1", "SHA 1"):
            self.assertEqual(canonicalize_algorithm(variant), "SHA-1", f"Failed for '{variant}'")

    def test_sha384_variants(self):
        for variant in ("SHA384", "SHA-384", "sha384"):
            self.assertEqual(canonicalize_algorithm(variant), "SHA-384", f"Failed for '{variant}'")

    def test_md5_variants(self):
        for variant in ("MD5", "md5", "Md5"):
            self.assertEqual(canonicalize_algorithm(variant), "MD5", f"Failed for '{variant}'")

    def test_aes256_variants(self):
        for variant in ("AES-256", "AES256", "aes256", "aes-256"):
            self.assertEqual(canonicalize_algorithm(variant), "AES-256", f"Failed for '{variant}'")

    def test_api_names_resolve_to_algorithm(self):
        """A.1: API call names map to the underlying algorithm."""
        self.assertEqual(canonicalize_algorithm("md5.New"), "MD5")
        self.assertEqual(canonicalize_algorithm("sha1.New"), "SHA-1")
        self.assertEqual(canonicalize_algorithm("sha256.New"), "SHA-256")
        self.assertEqual(canonicalize_algorithm("rsa.GenerateKey"), "RSA")
        self.assertEqual(canonicalize_algorithm("ecdsa.GenerateKey"), "ECDSA")
        self.assertEqual(canonicalize_algorithm("aes.NewCipher"), "AES")
        self.assertEqual(canonicalize_algorithm("hmac.New"), "HMAC")
        self.assertEqual(canonicalize_algorithm("crypto.createHmac"), "HMAC")

    def test_pqc_algorithms(self):
        self.assertEqual(canonicalize_algorithm("ML-KEM-768"), "ML-KEM-768")
        self.assertEqual(canonicalize_algorithm("ml-dsa-65"), "ML-DSA-65")

    def test_3des_variants(self):
        for variant in ("3DES", "DESede", "TripleDES", "DES3", "3des"):
            self.assertEqual(canonicalize_algorithm(variant), "3DES", f"Failed for '{variant}'")


class TestBareKeywordExclusion(TestCase):
    """A.2: Bare keywords are not cryptographic assets."""

    def test_bare_keywords_detected(self):
        self.assertTrue(is_bare_indicator("crypto", "unknown", "algorithm"))
        self.assertTrue(is_bare_indicator("KEY", "unknown", "algorithm"))
        self.assertTrue(is_bare_indicator("TLS", "unknown", "algorithm"))
        self.assertTrue(is_bare_indicator("tls", "unknown", "algorithm"))
        self.assertTrue(is_bare_indicator("HASH", "unknown", "algorithm"))
        self.assertTrue(is_bare_indicator("openssl_conf", "unknown", "algorithm"))
        self.assertTrue(is_bare_indicator("ssh_host_key", "unknown", "algorithm"))
        self.assertTrue(is_bare_indicator("tls_ciphers", "unknown", "algorithm"))

    def test_real_algorithms_not_excluded(self):
        self.assertFalse(is_bare_indicator("RSA-2048", "rsa", "algorithm"))
        self.assertFalse(is_bare_indicator("AES-256", "aes", "algorithm"))
        self.assertFalse(is_bare_indicator("SHA-256", "hash", "algorithm"))
        self.assertFalse(is_bare_indicator("MD5", "hash", "algorithm"))

    def test_bare_keywords_with_any_family_detected(self):
        """Bare keywords (hash, tls, key, crypto) must be indicators regardless of family."""
        self.assertTrue(is_bare_indicator("hash", "hash", "algorithm"))
        self.assertTrue(is_bare_indicator("tls", "rsa", "algorithm"))
        self.assertTrue(is_bare_indicator("key", "rsa", "key"))
        self.assertTrue(is_bare_indicator("crypto", "aes", "algorithm"))


class TestKeySizeValidation(TestCase):
    """A.3: Key sizes should not be assigned to hash/MAC findings."""

    def test_hash_key_size_rejected(self):
        self.assertIsNone(_validate_key_size(2048, "hash", "SHA-256"))
        self.assertIsNone(_validate_key_size(256, "hash", "MD5"))
        self.assertIsNone(_validate_key_size(512, "mac", "HMAC-SHA-256"))

    def test_rsa_key_size_accepted(self):
        self.assertEqual(_validate_key_size(2048, "rsa", "RSA-2048"), 2048)
        self.assertEqual(_validate_key_size(4096, "rsa", "RSA-4096"), 4096)

    def test_aes_key_size_accepted(self):
        self.assertEqual(_validate_key_size(256, "aes", "AES-256"), 256)

    def test_invalid_key_size_rejected(self):
        self.assertIsNone(_validate_key_size(0, "rsa", "RSA"))
        self.assertIsNone(_validate_key_size(-1, "rsa", "RSA"))
        self.assertIsNone(_validate_key_size(None, "rsa", "RSA"))
        self.assertIsNone(_validate_key_size("abc", "rsa", "RSA"))


class TestEvidenceContext(TestCase):
    """A.4: Evidence context and confidence tagging."""

    def test_certificate_context(self):
        self.assertEqual(_infer_source_context("", "certificate", ""), "certificate")

    def test_test_file_context(self):
        self.assertEqual(_infer_source_context("tests/test_crypto.py", "algorithm", "source_code"), "test")
        self.assertEqual(_infer_source_context("spec/crypto_spec.rb", "algorithm", "source_code"), "test")

    def test_docs_context(self):
        self.assertEqual(_infer_source_context("docs/readme.md", "algorithm", "source_code"), "docs")

    def test_config_context(self):
        self.assertEqual(_infer_source_context("config/ssl.conf", "algorithm", "source_code"), "config")

    def test_live_code_default(self):
        self.assertEqual(_infer_source_context("src/auth/session.py", "algorithm", "source_code"), "live_code")

    def test_confidence_levels(self):
        self.assertGreater(
            _compute_evidence_confidence("certificate", 0.9),
            _compute_evidence_confidence("test", 0.5)
        )
        self.assertGreater(
            _compute_evidence_confidence("live_code", 0.8),
            _compute_evidence_confidence("docs", 0.3)
        )


# ==========================================================================
# Phase B — Classification Correctness Tests
# ==========================================================================

class TestClassificationCorrectness(TestCase):
    """Phase B: Exact golden-fixture classification tests."""

    def test_rsa_2048_is_shor_vulnerable(self):
        profile = classify_crypto_security(algorithm="RSA-2048", family="rsa", key_size=2048)
        self.assertTrue(profile.is_shor_vulnerable)
        self.assertEqual(profile.risk_key, "vulnerable")
        self.assertEqual(profile.quantum_threat_class, QuantumThreatClass.SHOR_VULNERABLE)

    def test_ecdsa_p256_is_shor_vulnerable(self):
        profile = classify_crypto_security(algorithm="ECDSA-P256", family="ecc", curve="P-256")
        self.assertTrue(profile.is_shor_vulnerable)
        self.assertEqual(profile.risk_key, "vulnerable")

    def test_aes_256_gcm_is_moderate(self):
        profile = classify_crypto_security(algorithm="AES-256-GCM", family="aes", key_size=256)
        self.assertFalse(profile.is_shor_vulnerable)
        self.assertEqual(profile.risk_key, "moderate")
        self.assertIn("Retain", profile.recommended_action)

    def test_md5_is_broken_not_shor(self):
        profile = classify_crypto_security(algorithm="MD5", family="hash")
        self.assertFalse(profile.is_shor_vulnerable)
        self.assertEqual(profile.risk_key, "weak")
        self.assertEqual(profile.classical_status, ClassicalSecurityStatus.BROKEN)

    def test_sha1_is_deprecated_not_shor(self):
        profile = classify_crypto_security(algorithm="SHA-1", family="hash")
        self.assertFalse(profile.is_shor_vulnerable)
        self.assertEqual(profile.risk_key, "weak")

    def test_des_is_broken_not_shor(self):
        profile = classify_crypto_security(algorithm="DES", family="des3")
        self.assertFalse(profile.is_shor_vulnerable)
        self.assertEqual(profile.risk_key, "weak")

    def test_3des_is_deprecated_not_shor(self):
        profile = classify_crypto_security(algorithm="3DES")
        self.assertFalse(profile.is_shor_vulnerable)
        self.assertEqual(profile.risk_key, "weak")

    def test_rc4_is_broken_not_shor(self):
        profile = classify_crypto_security(algorithm="RC4")
        self.assertFalse(profile.is_shor_vulnerable)
        self.assertEqual(profile.risk_key, "weak")

    def test_rc2_is_broken_not_shor(self):
        profile = classify_crypto_security(algorithm="RC2")
        self.assertFalse(profile.is_shor_vulnerable)
        self.assertEqual(profile.risk_key, "weak")

    def test_blowfish_is_deprecated_not_shor(self):
        profile = classify_crypto_security(algorithm="Blowfish")
        self.assertFalse(profile.is_shor_vulnerable)
        self.assertEqual(profile.risk_key, "weak")

    def test_sha256_is_retain_strong(self):
        profile = classify_crypto_security(algorithm="SHA-256", family="hash")
        self.assertFalse(profile.is_shor_vulnerable)
        self.assertEqual(profile.risk_key, "moderate")
        self.assertIn("Retain", profile.recommended_action)

    def test_sha384_is_retain_strong(self):
        profile = classify_crypto_security(algorithm="SHA-384", family="hash")
        self.assertFalse(profile.is_shor_vulnerable)
        self.assertEqual(profile.risk_key, "moderate")

    def test_sha512_is_retain_strong(self):
        profile = classify_crypto_security(algorithm="SHA-512", family="hash")
        self.assertFalse(profile.is_shor_vulnerable)
        self.assertEqual(profile.risk_key, "moderate")
        self.assertNotIn("Strengthen", profile.recommended_action)

    def test_hmac_sha1_is_legacy_review_not_weak(self):
        """B.2: HMAC-SHA-1 is Legacy-Review, NOT Weak, NOT Retain(Strong)."""
        profile = classify_crypto_security(algorithm="HMAC-SHA-1")
        self.assertFalse(profile.is_shor_vulnerable)
        self.assertEqual(profile.classical_status, ClassicalSecurityStatus.LEGACY_REVIEW)
        # Should NOT be "weak" — HMAC construction protects against collision attacks
        self.assertNotEqual(profile.risk_key, "weak")
        # Should NOT be "Retain (Strong)" — SHA-1 is deprecated
        self.assertNotIn("Retain (Strong)", profile.recommended_action)
        self.assertIn("HMAC-SHA-256", profile.recommended_action)

    def test_md5_new_inherits_md5_classification(self):
        """B.1: md5.New must inherit MD5's classification (never Moderate)."""
        canonical = canonicalize_algorithm("md5.New")
        self.assertEqual(canonical, "MD5")
        profile = classify_crypto_security(algorithm=canonical, family="hash")
        self.assertEqual(profile.risk_key, "weak")
        self.assertEqual(profile.classical_status, ClassicalSecurityStatus.BROKEN)

    def test_sha1_new_inherits_sha1_classification(self):
        """B.1: sha1.New must inherit SHA-1's classification."""
        canonical = canonicalize_algorithm("sha1.New")
        self.assertEqual(canonical, "SHA-1")
        profile = classify_crypto_security(algorithm=canonical, family="hash")
        self.assertEqual(profile.risk_key, "weak")

    def test_rsa_below_2048_is_deprecated(self):
        """B.1: RSA/DSA < 2048 bits must be classically deprecated."""
        profile = classify_crypto_security(algorithm="RSA-1024", family="rsa", key_size=1024)
        self.assertTrue(profile.is_shor_vulnerable)
        self.assertEqual(profile.classical_status, ClassicalSecurityStatus.DEPRECATED)

    def test_ecdh_gets_kem_recommendation(self):
        """B.4: ECDH gets KEM recommendation, not signature."""
        profile = classify_crypto_security(algorithm="ECDH", family="ecc", role="key_exchange")
        self.assertTrue(profile.is_shor_vulnerable)
        self.assertIn("ML-KEM", profile.recommended_action)

    def test_ecdsa_gets_signature_recommendation(self):
        """B.4: ECDSA gets signature recommendation, not KEM."""
        profile = classify_crypto_security(algorithm="ECDSA", family="ecc")
        self.assertTrue(profile.is_shor_vulnerable)
        self.assertIn("ML-DSA", profile.recommended_action)

    def test_pqc_ml_kem_is_pqc_ready(self):
        profile = classify_crypto_security(algorithm="ML-KEM-768", family="pqc")
        self.assertFalse(profile.is_shor_vulnerable)
        self.assertEqual(profile.risk_key, "pqc")

    def test_md5_password_hashing_recommends_argon2(self):
        """B.3: MD5 for password hashing gets Argon2id recommendation."""
        profile = classify_crypto_security(algorithm="MD5", role="password")
        self.assertEqual(profile.risk_key, "weak")
        self.assertIn("Argon2id", profile.recommended_action)


# ==========================================================================
# Phase C — ThreatContext & Invariant Tests
# ==========================================================================

class TestThreatContext(TestCase):
    """Phase C: Unified threat context."""

    def test_default_mosca_parameters(self):
        ctx = ThreatContext()
        self.assertEqual(ctx.migration_years_x, 3.0)
        self.assertEqual(ctx.data_shelf_life_y, 8.0)
        self.assertEqual(ctx.crqc_year_z, 2033)
        self.assertEqual(ctx.assessment_year, 2026)
        self.assertEqual(ctx.years_until_crqc, 7.0)

    def test_mosca_deficit(self):
        ctx = ThreatContext(migration_years_x=3.0, data_shelf_life_y=8.0, crqc_year_z=2033, assessment_year=2026)
        # X + Y = 11, Z = 7, deficit = 4
        self.assertEqual(ctx.mosca_deficit, 4.0)
        self.assertTrue(ctx.mosca_at_risk)

    def test_mosca_safe(self):
        ctx = ThreatContext(migration_years_x=1.0, data_shelf_life_y=2.0, crqc_year_z=2033, assessment_year=2026)
        # X + Y = 3, Z = 7, deficit = -4
        self.assertLess(ctx.mosca_deficit, 0.0)
        self.assertFalse(ctx.mosca_at_risk)

    def test_migration_deadline_year(self):
        ctx = ThreatContext(migration_years_x=3.0, crqc_year_z=2033)
        self.assertEqual(ctx.migration_deadline_year, 2030)

    def test_resolve_with_overrides(self):
        ctx = resolve_threat_context(
            run_parameters={"migration_time_years": 5.0},
            user_overrides={"migration_years": 2.0},
        )
        # Override wins
        self.assertEqual(ctx.migration_years_x, 2.0)

    def test_resolve_conflict_uses_conservative(self):
        ctx = resolve_threat_context(
            run_parameters={"network_exposure": "internal"},
            digital_twin={"contexts": {"exposure": "public"}},
        )
        # More conservative (public) should win
        self.assertEqual(ctx.network_exposure, "public")

    def test_hndl_not_assessable_when_missing_inputs(self):
        ctx = ThreatContext()
        assessable, reason = ctx.check_hndl_assessability()
        self.assertFalse(assessable)
        self.assertIn("Missing", reason)

    def test_hndl_assessable_when_complete(self):
        ctx = ThreatContext(
            data_sensitivity="high",
            data_types=["PII", "financial"],
        )
        ctx.defaulted_params = []  # Not defaulted
        assessable, _ = ctx.check_hndl_assessability()
        self.assertTrue(assessable)


class TestAnalysisInvariants(TestCase):
    """Phase C.5: Post-analysis invariant checks."""

    def test_mosca_at_risk_with_no_urgent(self):
        ctx = ThreatContext(migration_years_x=5.0, data_shelf_life_y=8.0)
        assets = [
            {"name": "RSA-2048", "quantum_vulnerable": True, "priority": "LOW", "risk_key": "vulnerable"},
        ]
        summary = {"vulnerable": 1, "weak": 0, "moderate": 0, "pqc": 0, "unknown": 0}
        warnings = validate_analysis_invariants(assets, ctx, summary, summary)
        self.assertTrue(any("Mosca" in w for w in warnings))

    def test_weak_asset_below_medium(self):
        ctx = ThreatContext()
        assets = [
            {"name": "DES", "risk_key": "weak", "priority": "LOW"},
        ]
        summary = {"vulnerable": 0, "weak": 1, "moderate": 0, "pqc": 0, "unknown": 0}
        warnings = validate_analysis_invariants(assets, ctx, summary, summary)
        self.assertTrue(any("below MEDIUM" in w for w in warnings))

    def test_count_mismatch(self):
        ctx = ThreatContext()
        summary = {"vulnerable": 5, "weak": 0, "moderate": 0, "pqc": 0, "unknown": 0}
        table = {"vulnerable": 3, "weak": 0, "moderate": 0, "pqc": 0, "unknown": 0}
        warnings = validate_analysis_invariants([], ctx, summary, table)
        self.assertTrue(any("disagrees" in w for w in warnings))


# ==========================================================================
# Phase D — Mitigation Wave & Effort Tests
# ==========================================================================

class TestMigrationWaves(TestCase):
    """Phase D: Wave logic tests."""

    def test_classical_weak_in_wave_1(self):
        """Classical-weak security-use algorithms must be Wave 1."""
        for algo in ("MD5", "SHA-1", "DES", "3DES", "RC4", "RC2", "BLOWFISH"):
            wave = migration_wave_for(
                {"algorithm": algo, "algorithm_category": "CLASSICAL_WEAK", "migration_priority": "HIGH"},
                {"severity": "MEDIUM"},
            )
            self.assertEqual(wave, 1, f"{algo} should be Wave 1, got {wave}")

    def test_shor_vulnerable_pubkey_in_wave_2(self):
        """Non-urgent Shor-vulnerable public key assets should be Wave 2."""
        wave = migration_wave_for(
            {"algorithm": "RSA-2048", "algorithm_category": "PUBLIC_KEY",
             "quantum_vulnerable": True, "migration_priority": "HIGH"},
            {"severity": "HIGH"},
        )
        self.assertEqual(wave, 2)

    def test_hndl_exposed_shor_vuln_in_wave_1(self):
        """HNDL-exposed Shor-vulnerable assets should be Wave 1."""
        wave = migration_wave_for(
            {"algorithm": "RSA-2048", "algorithm_category": "PUBLIC_KEY",
             "quantum_vulnerable": True, "hndl_risk": "HIGH"},
            {"severity": "HIGH"},
        )
        self.assertEqual(wave, 1)

    def test_symmetric_in_wave_3(self):
        """Symmetric hardening should be Wave 3."""
        wave = migration_wave_for(
            {"algorithm": "AES-128", "algorithm_category": "SYMMETRIC",
             "quantum_vulnerable": False, "migration_priority": "MEDIUM"},
            {"severity": "LOW"},
        )
        self.assertEqual(wave, 3)

    def test_wave_defs_have_criteria(self):
        """Wave definitions must include criteria for documentation."""
        for wave_def in WAVE_DEFS:
            self.assertIn("criteria", wave_def)
            self.assertIn("focus", wave_def)
            self.assertIn("timeline", wave_def)


class TestEffortEstimation(TestCase):
    """Phase D: Effort range estimation."""

    def test_empty_assets_zero_effort(self):
        result = compute_effort_range([])
        self.assertEqual(result["low_weeks"], 0.0)
        self.assertEqual(result["high_weeks"], 0.0)

    def test_effort_has_range(self):
        assets = [
            {"algorithm": "RSA-2048", "algorithm_category": "PUBLIC_KEY", "service": "auth"},
            {"algorithm": "DES", "algorithm_category": "CLASSICAL_WEAK", "service": "storage"},
        ]
        result = compute_effort_range(assets)
        self.assertGreater(result["low_weeks"], 0)
        self.assertGreater(result["high_weeks"], result["low_weeks"])
        self.assertIn("assumptions", result)
        self.assertGreater(len(result["assumptions"]), 0)

    def test_deduplication(self):
        """Same algo+service should be counted once."""
        assets = [
            {"algorithm": "RSA-2048", "algorithm_category": "PUBLIC_KEY", "service": "auth"},
            {"algorithm": "RSA-2048", "algorithm_category": "PUBLIC_KEY", "service": "auth"},
        ]
        result = compute_effort_range(assets)
        self.assertEqual(result["deduplicated_tasks"], 1)


class TestStandardsProfile(TestCase):
    """Phase D.5: Standards profile setting."""

    def test_nist_general_default(self):
        recs = get_standards_recommendations("nist_general")
        self.assertIn("ML-KEM-768", recs["kem"])

    def test_cnsa_2_0(self):
        recs = get_standards_recommendations("cnsa_2_0")
        self.assertEqual(recs["kem"], "ML-KEM-1024 (FIPS 203)")
        self.assertEqual(recs["signature"], "ML-DSA-87 (FIPS 204)")
        self.assertIn("LMS", recs["firmware_signing"])


class TestMitigation_HMAC_SHA1(TestCase):
    """Phase D: HMAC-SHA-1 mitigation handling."""

    def test_hmac_sha1_migration_impact(self):
        impact = compute_migration_impact({"algorithm": "HMAC-SHA-1", "family": "mac"})
        self.assertIn("HMAC-SHA-256", impact["replacement"])
        self.assertEqual(impact["replacement_category"], "LEGACY_REVIEW")


# ==========================================================================
# Phase E — Report Terminology Tests
# ==========================================================================

class TestReportTerminology(TestCase):
    """Phase E: Terminology and label correctness."""

    def test_sha512_not_downgraded_in_classification(self):
        """SHA-512 must be Retain(Strong), never 'Strengthen SHA-512 to SHA-256'."""
        profile = classify_crypto_security(algorithm="SHA-512", family="hash")
        self.assertNotIn("Strengthen", profile.recommended_action)
        self.assertNotIn("downgrade", profile.rationale.lower())

    def test_des_recommendation_is_migration_not_maintain(self):
        """DES remediation must be migration to AES-256-GCM, never 'Maintain DES'."""
        profile = classify_crypto_security(algorithm="DES")
        self.assertNotIn("Maintain", profile.recommended_action)
        self.assertIn("AES-256-GCM", profile.recommended_action)

    def test_blowfish_recommendation_is_migration(self):
        """Blowfish remediation must be migration, never 'Maintain Blowfish'."""
        profile = classify_crypto_security(algorithm="Blowfish")
        self.assertNotIn("Maintain", profile.recommended_action)

    def test_md5_never_shor_in_any_path(self):
        """MD5 must never be classified as Shor-vulnerable through any code path."""
        for role in ("", "password", "certificate", "checksum", "signing"):
            profile = classify_crypto_security(algorithm="MD5", role=role)
            self.assertFalse(profile.is_shor_vulnerable, f"MD5 with role='{role}' should not be Shor-vulnerable")

    def test_family_guesser_handles_api_names(self):
        """_guess_family_from_algorithm should handle API names via canonicalization."""
        family = _guess_family_from_algorithm("hashlib.md5")
        self.assertEqual(family, "hash")


class TestClassifyAssetBareKeywordFilter(TestCase):
    """Ensure classify_asset strictly returns None for bare keywords."""

    def test_classify_asset_rejects_bare_keywords(self):
        from unittest.mock import MagicMock
        from segments.scraping.discovery.classifier import classify_asset

        for keyword in ("crypto", "KEY", "TLS", "tls", "HASH", "openssl_conf", "ssh_host_key", "tls_ciphers"):
            mock_finding = MagicMock()
            mock_finding.algorithm = keyword
            mock_finding.family = "unknown"
            mock_finding.kind = "algorithm"
            mock_finding.evidence = {"is_indicator": True}
            result = classify_asset(mock_finding)
            self.assertIsNone(result, f"classify_asset should return None for bare keyword '{keyword}'")


class TestFakeKeySizeRejection(TestCase):
    """Ensure non-key primitives never receive key sizes."""

    def test_fake_key_sizes_rejected(self):
        from segments.scraping.discovery.normalizer import _validate_key_size
        self.assertIsNone(_validate_key_size(2048, "hash", "HASH"))
        self.assertIsNone(_validate_key_size(2048, "protocol", "TLS"))
        self.assertIsNone(_validate_key_size(2048, "unknown", "KEY"))
        self.assertIsNone(_validate_key_size(256, "hash", "SHA-256"))
        self.assertIsNone(_validate_key_size(512, "hash", "SHA-512"))
        self.assertIsNone(_validate_key_size(512, "hash", "HASH"))


class TestReportInvariantsEvaluation(TestCase):
    """Ensure _evaluate_invariants runs and passes on valid report data."""

    def test_evaluate_invariants_clean_pass(self):
        from segments.reporting.reports.report_builder import _evaluate_invariants
        sample_data = {
            "kpis": {
                "assets": 3,
                "risk_counts": {"vulnerable": 1, "weak": 1, "moderate": 1, "pqc": 0, "unknown": 0},
            },
            "assets": [
                {"name": "Auth Signing", "risk_key": "vulnerable", "replacement": "ML-DSA-65", "score": 90},
                {"name": "Legacy Hash", "risk_key": "weak", "replacement": "SHA-256", "score": 80},
                {"name": "Data Encryption", "risk_key": "moderate", "replacement": "AES-256", "score": 50},
            ],
            "runs": [
                {
                    "stats": {"assets": 3, "urgent": 1, "critical": 1, "hndl_applicable": 1},
                    "rows": [{"overall_risk": "HIGH", "migration_priority": "URGENT"}],
                }
            ],
            "mitigation": {
                "enhanced": False,
                "summary": {
                    "wave1": 1,
                    "wave2": 1,
                    "wave3": 1,
                    "effort_low_quarters": 1.0,
                    "effort_high_quarters": 2.5,
                },
                "rows": [{"asset_id": "A1"}, {"asset_id": "A2"}, {"asset_id": "A3"}],
            },
        }
        invariants = _evaluate_invariants(sample_data)
        self.assertEqual(len(invariants), 10)
        for inv in invariants:
            self.assertTrue(inv["passed"], f"Invariant failed: {inv['name']} - {inv['detail']}")


class TestPathSanitization(TestCase):
    """Ensure absolute local paths and developer home dirs are redacted."""

    def test_sanitize_windows_paths(self):
        from segments.reporting.reports.report_builder import _sanitize_path
        self.assertNotIn("C:", _sanitize_path(r"C:\Users\Lenovo\Downloads\ECDAT_Demo_Assets_120"))
        self.assertNotIn("Users", _sanitize_path(r"C:\Users\Lenovo\Downloads\ECDAT_Demo_Assets_120"))
        self.assertNotIn("Lenovo", _sanitize_path(r"C:\Users\Lenovo\Desktop\ECDAT\ECDAT\services\app.py"))
        self.assertEqual(_sanitize_path(r"C:\Users\Lenovo\Downloads\ECDAT_Demo_Assets_120"), "ECDAT_Demo_Assets_120")
        self.assertEqual(_sanitize_path(r"services\service_001_rsa.py"), "./services/service_001_rsa.py")
        self.assertNotIn("home", _sanitize_path("/home/developer/workspace/app.py"))
        self.assertNotIn("Users", _sanitize_path("/Users/developer/workspace/app.py"))


class TestRoleSeparationAndRecommendations(TestCase):
    """Ensure ECDSA, ECDH, Ed25519, and RSA roles receive distinct PQC guidance."""

    def test_ecdsa_vs_ecdh_distinction(self):
        from unittest.mock import MagicMock
        from segments.reporting.dashboard.views import _pqc_replacement

        ecdsa_asset = MagicMock(family="ecc", algorithm="ECDSA", role="signature", name="sign_key")
        ecdh_asset = MagicMock(family="ecc", algorithm="ECDH", role="key_exchange", name="tls_exchange")
        ed25519_asset = MagicMock(family="ecc", algorithm="Ed25519", role="signature", name="auth_token")

        ecdsa_rec = _pqc_replacement(ecdsa_asset)
        ecdh_rec = _pqc_replacement(ecdh_asset)
        ed25519_rec = _pqc_replacement(ed25519_asset)

        self.assertIn("ML-DSA", ecdsa_rec)
        self.assertNotIn("ML-KEM", ecdsa_rec)

        self.assertIn("ML-KEM", ecdh_rec)

        self.assertIn("ML-DSA", ed25519_rec)
        self.assertNotIn("ML-KEM", ed25519_rec)


class TestCNSA20Validation(TestCase):
    """Ensure CNSA 2.0 profile strictly emits CNSA-approved algorithms only."""

    def test_cnsa_profile_rejection_of_non_cnsa(self):
        from segments.mitigation.mitigation_agent.rules import get_standards_recommendations, compute_migration_impact
        cnsa_recs = get_standards_recommendations("cnsa_2_0")
        self.assertNotIn("ML-KEM-768", cnsa_recs["kem"])
        self.assertNotIn("ML-DSA-65", cnsa_recs["signature"])
        self.assertIn("ML-KEM-1024", cnsa_recs["kem"])
        self.assertIn("ML-DSA-87", cnsa_recs["signature"])

        # Direct asset impact tests under CNSA 2.0
        ecdsa_cnsa = compute_migration_impact({"algorithm": "ECDSA", "standards_profile": "cnsa_2_0"})
        self.assertEqual(ecdsa_cnsa["replacement"], "ML-DSA-87 (FIPS 204)")
        self.assertNotIn("ML-DSA-65", ecdsa_cnsa["replacement"])

        ecdh_cnsa = compute_migration_impact({"algorithm": "ECDH", "standards_profile": "cnsa_2_0"})
        self.assertEqual(ecdh_cnsa["replacement"], "ML-KEM-1024 (FIPS 203)")
        self.assertNotIn("ML-KEM-768", ecdh_cnsa["replacement"])

        rsa_sig_cnsa = compute_migration_impact({
            "algorithm": "RSA-2048",
            "standards_profile": "cnsa_2_0",
            "crypto_role": "digital_signature",
        })
        self.assertEqual(rsa_sig_cnsa["replacement"], "ML-DSA-87 (FIPS 204)")

        rsa_enc_cnsa = compute_migration_impact({
            "algorithm": "RSA-2048",
            "standards_profile": "cnsa_2_0",
            "crypto_role": "key_establishment",
        })
        self.assertEqual(rsa_enc_cnsa["replacement"], "ML-KEM-1024 (FIPS 203)")


class TestRotationVsQuantumMigration(TestCase):
    """Ensure pure Shor exposure does not incorrectly recommend key rotation."""

    def test_pure_shor_recommends_algorithm_migration(self):
        from segments.mitigation.mitigation_agent.rules import suggestions_for
        asset_ctx = {
            "algorithm": "RSA-2048",
            "algorithm_category": "PUBLIC_KEY",
            "quantum_vulnerable": True,
            "migration_priority": "HIGH",
            "hndl_risk": "LOW",
            "key_hygiene_issue": False,
        }
        blast = {"service": "auth-service"}
        impact = {"replacement": "ML-KEM-768 / ML-DSA-65"}
        suggestions = suggestions_for(asset_ctx, blast, impact)

        # Primary suggestion must be algorithm migration, not rotate key now
        self.assertTrue(any("Migrate" in s for s in suggestions))
        self.assertFalse(any("Rotate expired" in s for s in suggestions))


class TestWeakAlgorithmCoverage(TestCase):
    """Ensure DES, 3DES/DESede, RC4, RC2, Blowfish, MD5, SHA-1, HMAC-SHA1 have correct semantics."""

    def test_weak_primitives_classification_and_priority_floor(self):
        from unittest.mock import MagicMock
        from segments.reporting.dashboard.views import _asset_risk, _priority_score, _pqc_replacement

        for algo in ["DES", "3DES", "DESede", "RC4", "Blowfish", "RC2", "MD5", "SHA-1"]:
            mock_asset = MagicMock(family="unknown", algorithm=algo, role="security", name=f"{algo} usage", key_size=None)
            key, label, _ = _asset_risk(mock_asset)
            score = _priority_score(mock_asset, key)
            self.assertEqual(key, "weak", f"{algo} should be weak")
            self.assertGreaterEqual(score, 70, f"{algo} priority score should be >= 70 (floor)")

        # MD5 / SHA-1 signature role -> weak security use
        sha1_sig = MagicMock(family="hash", algorithm="SHA-1", role="signature", name="cert sig", key_size=None)
        key, label, _ = _asset_risk(sha1_sig)
        score = _priority_score(sha1_sig, key)
        self.assertEqual(key, "weak")
        self.assertGreaterEqual(score, 70)

        # MD5 / SHA-1 checksum-only usage -> distinguishable from security use
        md5_chk = MagicMock(family="hash", algorithm="MD5", role="checksum", name="file hash", key_size=None)
        c_key, c_label, _ = _asset_risk(md5_chk)
        c_score = _priority_score(md5_chk, c_key)
        self.assertEqual(c_key, "moderate")
        self.assertIn("Checksum", c_label)
        self.assertLess(c_score, 70)

        sha1_chk = MagicMock(family="hash", algorithm="SHA-1", role="file_checksum", name="pkg hash", key_size=None)
        s_key, s_label, _ = _asset_risk(sha1_chk)
        self.assertEqual(s_key, "moderate")

        # Unknown role -> conservative security-use treatment
        md5_unk = MagicMock(family="hash", algorithm="MD5", role="", name="unknown md5", key_size=None)
        u_key, u_label, _ = _asset_risk(md5_unk)
        u_score = _priority_score(md5_unk, u_key)
        self.assertEqual(u_key, "weak")
        self.assertGreaterEqual(u_score, 70)

        # HMAC-SHA1 -> Legacy-Review (moderate), not Weak and not Retain (Strong)
        hmac_asset = MagicMock(family="mac", algorithm="HMAC-SHA1", role="mac", name="hmac token", key_size=None)
        h_key, h_label, _ = _asset_risk(hmac_asset)
        self.assertEqual(h_key, "moderate")
        self.assertIn("Legacy", h_label)
        h_rep = _pqc_replacement(hmac_asset)
        self.assertEqual(h_rep, "HMAC-SHA-256 / KMAC")
        self.assertNotIn("Retain (Strong)", h_rep)


class TestEd25519TerminologyAndFormatting(TestCase):
    """Verify Ed25519 naming, curve Edwards25519, and parameter display precision."""

    def test_ed25519_curve_and_parameter_display(self):
        from segments.reporting.reports.report_builder import _sec_inventory

        kpis = {
            "risk_counts": {"vulnerable": 1, "weak": 0, "moderate": 0, "pqc": 0, "unknown": 0},
            "assets": 1,
            "scans": 1,
            "raw_findings": 1,
            "normalized_findings": 1,
            "quantum_pct": 100,
        }
        assets = [
            {
                "name": "auth_service — Ed25519",
                "family": "ecc",
                "algorithm": "Ed25519",
                "key_size": 256,
                "curve": "Edwards25519",
                "risk_key": "vulnerable",
                "risk_label": "Vulnerable (Shor)",
                "replacement": "ML-DSA-65 (FIPS 204) / SLH-DSA",
            }
        ]

        html = _sec_inventory(kpis, assets, 1)

        # Must NOT label Ed25519 as Curve25519
        self.assertNotIn("256 (Curve25519)", html)
        self.assertIn("256 (Parameter)", html)
        self.assertIn("Edwards25519", html)
        self.assertIn("Ed25519", html)

    def test_x25519_curve_display(self):
        from segments.reporting.reports.report_builder import _sec_inventory

        kpis = {
            "risk_counts": {"vulnerable": 1, "weak": 0, "moderate": 0, "pqc": 0, "unknown": 0},
            "assets": 1,
            "scans": 1,
            "raw_findings": 1,
            "normalized_findings": 1,
            "quantum_pct": 100,
        }
        assets = [
            {
                "name": "tls_service — X25519",
                "family": "ecc",
                "algorithm": "X25519",
                "key_size": 256,
                "curve": "Curve25519",
                "risk_key": "vulnerable",
                "risk_label": "Vulnerable (Shor)",
                "replacement": "ML-KEM-768 (Hybrid X25519MLKEM768)",
            }
        ]

        html = _sec_inventory(kpis, assets, 1)
        self.assertIn("Curve25519", html)
        self.assertIn("256 (Parameter)", html)


class TestECDSAvsECDHNonCollapsing(TestCase):
    """Ensure ECDSA and ECDH do not collapse into one generic asset when evidence is distinguishable."""

    def test_distinguishable_evidence_preserves_identities(self):
        from segments.scraping.discovery.classifier import asset_identifier, asset_name
        from unittest.mock import MagicMock

        # Mock normalized findings for ECDSA and ECDH
        raw_ecdsa = MagicMock(location="auth/keys.py", source_type="source_code")
        raw_ecdh = MagicMock(location="transport/tls.py", source_type="source_code")

        norm_ecdsa = MagicMock(
            raw_finding=raw_ecdsa,
            algorithm="ECDSA",
            family="ecc",
            key_size=256,
            curve="secp256r1",
            protocol="",
            library="cryptography",
            evidence={},
            session_id="test_sess",
        )
        norm_ecdh = MagicMock(
            raw_finding=raw_ecdh,
            algorithm="ECDH",
            family="ecc",
            key_size=256,
            curve="secp256r1",
            protocol="",
            library="cryptography",
            evidence={},
            session_id="test_sess",
        )

        name_ecdsa = asset_name(norm_ecdsa, "source_code", "source_code")
        name_ecdh = asset_name(norm_ecdh, "source_code", "source_code")

        id_ecdsa = asset_identifier(name_ecdsa, "source_code", norm_ecdsa)
        id_ecdh = asset_identifier(name_ecdh, "source_code", norm_ecdh)

        self.assertNotEqual(name_ecdsa, name_ecdh)
        self.assertNotEqual(id_ecdsa, id_ecdh)
        self.assertIn("ECDSA", name_ecdsa)
        self.assertIn("ECDH", name_ecdh)


class TestDynamicWeakAlgorithmNarrative(TestCase):
    """Verify narrative is generated dynamically from actual weak assets without hardcoded DES."""

    def test_executive_summary_derives_weak_algos_dynamically(self):
        from segments.reporting.reports.report_builder import _sec_exec

        kpis = {
            "scans": 1,
            "raw_findings": 10,
            "normalized_findings": 5,
            "assets": 3,
            "families": 2,
            "quantum_vulnerable": 1,
            "classical_weak": 2,
            "relations": 0,
            "completed_runs": 1,
            "mitigation": 0,
            "quantum_pct": 33,
            "risk_counts": {"vulnerable": 1, "weak": 2, "moderate": 0, "pqc": 0, "unknown": 0},
        }

        # Dataset with MD5 and SHA-1, but NO DES
        assets_no_des = [
            {"name": "a1", "algorithm": "RSA-2048", "risk_key": "vulnerable"},
            {"name": "a2", "algorithm": "MD5", "risk_key": "weak"},
            {"name": "a3", "algorithm": "SHA-1", "risk_key": "weak"},
        ]

        html = _sec_exec(kpis, mitigation=None, assets=assets_no_des)

        # Must mention MD5 and SHA-1
        self.assertIn("MD5", html)
        self.assertIn("SHA-1", html)
        # Must NOT mention DES when DES is not in the dataset
        self.assertNotIn("DES", html)

    def test_executive_summary_includes_des_when_present(self):
        from segments.reporting.reports.report_builder import _sec_exec

        kpis = {
            "scans": 1,
            "raw_findings": 10,
            "normalized_findings": 5,
            "assets": 3,
            "families": 2,
            "quantum_vulnerable": 0,
            "classical_weak": 3,
            "relations": 0,
            "completed_runs": 1,
            "mitigation": 0,
            "quantum_pct": 0,
            "risk_counts": {"vulnerable": 0, "weak": 3, "moderate": 0, "pqc": 0, "unknown": 0},
        }

        # Dataset with DES, MD5, SHA-1
        assets_with_des = [
            {"name": "a1", "algorithm": "DES", "risk_key": "weak"},
            {"name": "a2", "algorithm": "MD5", "risk_key": "weak"},
            {"name": "a3", "algorithm": "SHA-1", "risk_key": "weak"},
        ]

        html = _sec_exec(kpis, mitigation=None, assets=assets_with_des)

        self.assertIn("DES", html)
        self.assertIn("MD5", html)
        self.assertIn("SHA-1", html)



