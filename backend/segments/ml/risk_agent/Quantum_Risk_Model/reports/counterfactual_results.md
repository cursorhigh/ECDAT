# ECDAT Quantum Risk ML Model — Controlled Counterfactual & Monotonicity Report

**Date:** 2026-09-25  
**Version:** 1.0.0  
**Test Suite:** `tests/test_counterfactuals.py` (5/5 tests passed, 18/18 total pytest suite passed)  
**Overall Behavioral Consistency:** **PASS**  

---

## 1. Executive Summary

A controlled counterfactual evaluation was executed against the production ECDAT Quantum Risk Model (`models/final/`). The goal was to systematically isolate the model's sensitivity along two primary dimensions:
1. **Cryptographic Primitive Vulnerability:** Swapping a Shor-vulnerable asymmetric algorithm (RSA-2048) for a post-quantum-resistant symmetric algorithm (AES-256) under identical peak operational context.
2. **Operational & Exposure Context:** Modulating enterprise context (data sensitivity, data lifetime, business criticality, migration timeline, HNDL exposure, and network exposure) between minimal, baseline, and extreme levels while holding the underlying cryptographic primitive (RSA-2048) fixed.

---

## 2. Counterfactual Results Table

| Test | Risk Level | LOW | MEDIUM | HIGH | CRITICAL | Confidence | Schema Valid |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Test 1 — Baseline RSA-2048** | **CRITICAL** | 0.0000 | 0.0000 | 0.0007 | **0.9993** | 0.9993 | PASS (0 err, 0 warn) |
| **Test 2 — AES-256 Counterfactual** | **CRITICAL** | 0.0056 | 0.1564 | 0.0131 | **0.8250** | 0.8250 | PASS (0 err, 0 warn) |
| **Test 3 — Low-Context RSA-2048** | **MEDIUM** | 0.0131 | **0.9866** | 0.0003 | 0.0000 | 0.9866 | PASS (0 err, 0 warn) |
| **Test 4 — Extreme RSA-2048** | **CRITICAL** | 0.0000 | 0.0000 | 0.0001 | **0.9999** | 0.9999 | PASS (0 err, 0 warn) |

---

## 3. Detailed Counterfactual Comparison & Feature Delta

### Test 2: RSA-2048 vs. AES-256 (Primitive Swap Only)
- **Features Changed (Cryptographic Primitives Only):**
  - `algorithm`: `RSA-2048` $\rightarrow$ `AES-256`
  - `algorithm_family`: `asymmetric` $\rightarrow$ `symmetric`
  - `crypto_role`: `key_establishment` $\rightarrow$ `encryption`
  - `key_or_hash_size_bits`: `2048` $\rightarrow$ `256`
  - `quantum_attack_type`: `Shor` $\rightarrow$ `Grover`
  - `quantum_vulnerable`: `1` $\rightarrow$ `0`
  - `classical_security_bits_est`: `112` $\rightarrow$ `256`
  - `nist_security_category`: `1` $\rightarrow$ `5`
  - `quantum_attack_scenario`: `notional_future` $\rightarrow$ `generic_quantum_effect`
  - `estimated_attack_time_log10_hours`: `4.5` $\rightarrow$ `null` (imputed)
  - `quantum_estimate_confidence`: `scenario-dependent` $\rightarrow$ `not-applicable`
- **Features Kept Identical (Contextual):**
  - `data_sensitivity` = 5, `business_criticality` = 5, `data_lifetime_years` = 15.0, `migration_time_years` = 3.5, `migration_complexity` = 5, `crypto_agility` = 2, `internet_exposed` = 1, `external_facing` = 1, `dependency_count` = 18, `downstream_system_count` = 9, `HNDL_exposure` = 0.85, `protocol` = "TLS1.2", `crypto_library` = "OpenSSL", `deployment_environment` = "cloud", `environment_context` = "financial", `implementation_age_years` = 4.0, `key_age_days` = 240, `key_rotation_interval_days` = 365, `certificate_remaining_days` = 120.
- **Observed Behavior:**
  - $P(\text{CRITICAL})$ reduced from $0.9993$ to $0.8250$ ($-17.43\%$).
  - Lower-tier probability mass ($P(\text{LOW}) + P(\text{MEDIUM})$) surged from $0.0000$ to $0.1620$ ($+16.20\%$).
  - **Verdict:** Consistent. The model correctly downweights risk when moving to a quantum-resistant symmetric primitive, while preserving appropriate risk elevation due to the severe enterprise context (Level 5 sensitivity, 15-year lifetime, 0.85 HNDL exposure).

---

### Test 3: Baseline RSA vs. Low-Context RSA (Context Reduction Only)
- **Features Changed (Operational & Contextual Factors Only):**
  - `data_sensitivity`: `5` $\rightarrow$ `1`
  - `business_criticality`: `5` $\rightarrow$ `1`
  - `data_lifetime_years`: `15.0` $\rightarrow$ `1.0`
  - `migration_time_years`: `3.5` $\rightarrow$ `0.5`
  - `migration_complexity`: `5` $\rightarrow$ `1`
  - `crypto_agility`: `2` $\rightarrow$ `5`
  - `internet_exposed`: `1` $\rightarrow$ `0`
  - `external_facing`: `1` $\rightarrow$ `0`
  - `HNDL_exposure`: `0.85` $\rightarrow$ `0.0`
  - `dependency_count`: `18` $\rightarrow$ `1`
  - `downstream_system_count`: `9` $\rightarrow$ `0`
  - `vendor_support_score`: `2` $\rightarrow$ `5`
  - `inventory_confidence`: `4` $\rightarrow$ `5`
  - `compliance_criticality`: `5` $\rightarrow$ `1`
  - `deployment_environment`: `"cloud"` $\rightarrow$ `"container"`
  - `environment_context`: `"financial"` $\rightarrow$ `"developer_ci"`
  - `key_age_days`: `240` $\rightarrow$ `30`
  - `key_rotation_interval_days`: `365` $\rightarrow$ `90`
  - `certificate_remaining_days`: `120` $\rightarrow$ `300`
- **Features Kept Identical (Cryptographic Identity):**
  - `algorithm` = "RSA-2048", `algorithm_family` = "asymmetric", `crypto_role` = "key_establishment", `key_or_hash_size_bits` = 2048, `quantum_attack_type` = "Shor", `quantum_vulnerable` = 1, `classical_security_bits_est` = 112, `nist_security_category` = 1, `deprecated_or_disallowed` = 0, `protocol` = "TLS1.2", `crypto_library` = "OpenSSL", `quantum_attack_scenario` = "notional_future", `quantum_estimate_confidence` = "scenario-dependent".
- **Observed Behavior:**
  - Predicted class shifted from **CRITICAL** $\rightarrow$ **MEDIUM**.
  - $P(\text{CRITICAL})$ plummeted from $0.9993$ to $0.0000$.
  - $P(\text{MEDIUM})$ climbed to $0.9866$.
  - **Verdict:** Consistent. The model does not suffer from single-feature myopia; a Shor-vulnerable algorithm deployed in an ephemeral, internal, non-sensitive context is reasonably classified as MEDIUM rather than CRITICAL.

---

### Test 4: Baseline RSA vs. Extreme High-Risk RSA (Context Elevation)
- **Features Changed (Context Escalated to Maximum):**
  - `data_lifetime_years`: `15.0` $\rightarrow$ `30.0`
  - `migration_time_years`: `3.5` $\rightarrow$ `3.8`
  - `crypto_agility`: `2` $\rightarrow$ `1` (least agile)
  - `HNDL_exposure`: `0.85` $\rightarrow$ `1.0` (maximum)
  - `dependency_count`: `18` $\rightarrow$ `120`
  - `downstream_system_count`: `9` $\rightarrow$ `45`
  - `vendor_support_score`: `2` $\rightarrow$ `1`
  - `inventory_confidence`: `4` $\rightarrow$ `1`
  - `key_reuse_detected`: `0` $\rightarrow$ `1`
  - `hardware_dependency`: `0` $\rightarrow$ `1`
  - `implementation_age_years`: `4.0` $\rightarrow$ `12.0`
  - `key_age_days`: `240` $\rightarrow$ `1500`
  - `key_rotation_interval_days`: `365` $\rightarrow$ `1000`
  - `certificate_remaining_days`: `120` $\rightarrow$ `15`
  - `estimated_attack_time_log10_hours`: `4.5` $\rightarrow$ `2.0`
- **Observed Behavior:**
  - $P(\text{CRITICAL})$ rose to $0.9999$ ($99.99\%$).
  - **Verdict:** Consistent. The model exhibits strong monotonic confidence saturation at extreme risk parameters.

---

## 4. Behavioral Consistency & Suspicious Behavior Assessment

1. **Schema Validation Compliance:** 100% of counterfactual cases passed schema validation with 0 errors and 0 warnings.
2. **Monotonicity Across Primitives:** $P(\text{CRITICAL})_{\text{AES-256}} \le P(\text{CRITICAL})_{\text{RSA-2048}}$ under identical operational conditions.
3. **Monotonicity Across Context:** $P(\text{CRITICAL})_{\text{Low-Context}} < P(\text{CRITICAL})_{\text{Baseline}} \le P(\text{CRITICAL})_{\text{Extreme}}$.
4. **Suspicious Model Behavior:** None detected. Predictions align logically with multi-factor risk interaction principles without hardcoded class collapse.
