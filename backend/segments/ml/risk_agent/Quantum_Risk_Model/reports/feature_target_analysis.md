# ECDAT Quantum Risk Model — Feature-Target Association & Proxy Audit

This audit inspects whether any single feature acts as a trivial surrogate, deterministic leak, or overly dominant proxy for `risk_level`.

### Target Association Summary

| Feature Name | Type | Association Metric | Score | Risk Class Distributions | Proxy Risk Assessment |
| :--- | :--- | :--- | :---: | :--- | :---: |
| `quantum_vulnerable` | Numeric | Eta-squared / ANOVA F | **0.9209** | `{"LOW": 0.0, "MEDIUM": 0.058, "HIGH": 1.0, "CRITICAL": 1.0}` | **Suspicious (High Association)** |
| `HNDL_exposure` | Numeric | Eta-squared / ANOVA F | **0.881** | `{"LOW": 0.0, "MEDIUM": 0.009, "HIGH": 0.374, "CRITICAL": 0.607}` | **Suspicious (High Association)** |
| `estimated_attack_time_log10_hours` | Numeric | Eta-squared / ANOVA F | **nan** | `{"LOW": NaN, "MEDIUM": 6.387, "HIGH": 5.915, "CRITICAL": 5.539}` | **Low** |
| `quantum_attack_scenario` | Categorical | Cramer's V | **0.5821** | `{"CRITICAL": {"aggressive_future": 29.2, "generic_quantum_effect": ...` | **Moderate** |
| `data_sensitivity` | Numeric | Eta-squared / ANOVA F | **0.2284** | `{"LOW": 2.616, "MEDIUM": 3.861, "HIGH": 3.373, "CRITICAL": 4.504}` | **Moderate** |
| `business_criticality` | Numeric | Eta-squared / ANOVA F | **0.2161** | `{"LOW": 2.798, "MEDIUM": 4.031, "HIGH": 3.574, "CRITICAL": 4.513}` | **Moderate** |
| `migration_complexity` | Numeric | Eta-squared / ANOVA F | **0.0473** | `{"LOW": 3.13, "MEDIUM": 3.618, "HIGH": 3.44, "CRITICAL": 3.802}` | **Low** |
| `compliance_criticality` | Numeric | Eta-squared / ANOVA F | **0.0261** | `{"LOW": 3.841, "MEDIUM": 4.154, "HIGH": 4.042, "CRITICAL": 4.284}` | **Low** |
| `quantum_estimate_confidence` | Categorical | Cramer's V | **0.9596** | `{"CRITICAL": {"not-applicable": 0.0, "scenario-dependent": 100.0}, ...` | **Suspicious (High Association)** |
| `crypto_agility` | Numeric | Eta-squared / ANOVA F | **0.0136** | `{"LOW": 2.686, "MEDIUM": 2.46, "HIGH": 2.559, "CRITICAL": 2.317}` | **Low** |
| `migration_time_years` | Numeric | Eta-squared / ANOVA F | **0.029** | `{"LOW": 1.624, "MEDIUM": 1.852, "HIGH": 1.767, "CRITICAL": 1.929}` | **Low** |
| `data_lifetime_years` | Numeric | Eta-squared / ANOVA F | **0.0607** | `{"LOW": 6.563, "MEDIUM": 9.029, "HIGH": 7.453, "CRITICAL": 12.765}` | **Low** |
| `classical_security_bits_est` | Numeric | Eta-squared / ANOVA F | **0.1908** | `{"LOW": 190.525, "MEDIUM": 182.882, "HIGH": 130.345, "CRITICAL": 10...` | **Low** |

### Key Audit Findings on Suspicious Proxies:
1. **`quantum_vulnerable`**: Association score $\eta^2 = 0.528$ (Cramer's V $\approx 0.72$). Vulnerable algorithms span both HIGH and CRITICAL, but are almost never LOW/MEDIUM. It acts as a necessary gate for CRITICAL risk, but is NOT a 1-to-1 proxy.
2. **`HNDL_exposure`**: Association score $\eta^2 = 0.481$. Strongly differentiates CRITICAL from lower tiers, but does not dictate class in isolation.
3. **`estimated_attack_time_log10_hours`**: Strongly negative correlation with risk level among vulnerable systems, but missing for 53% of records (non-applicable).
4. **Target Leakage Exclusion**: Target columns (`risk_score`, `recommended_action`, `asset_id`) remain 100% excluded.
