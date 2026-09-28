# ECDAT Quantum Risk ML Model — Deep Introspection & Explainability Report

**Date:** 2026-09-25  
**Model Version:** 1.0.0 (`CatBoostClassifier`)  
**Artifact Directory:** `models/final/`  
**Evaluation Set:** 15,000 Validation Records & 15,000 Test Records  
**Overall Introspection Status:** **PASS WITH WARNINGS** (Synthetic Data Domain)  

---

> [!WARNING]
> ### MANDATORY SYNTHETIC-DATA NOTICE
> **High predictive performance on this dataset demonstrates consistency with the synthetic label-generation process, not real-world quantum-risk prediction accuracy.**
> The underlying 100,000-record dataset was synthetically generated according to domain-heuristic mathematical formulations. High macro F1 ($0.930$) and low Expected Calibration Error ($1.4\%$) validate that the machine learning pipeline has faithfully and robustly learned the parameterized multidimensional risk surface without overfitting or data leakage. It does not constitute empirical validation against real-world post-quantum cryptographic breaches.

---

## 1. Global Feature Importance & Hierarchy

Global feature importance was evaluated using two independent methods:
1. **Tree-Split Importance:** CatBoost's internal feature importance metric.
2. **Permutation Importance:** Mean drop in Macro F1 upon shuffling feature columns on the untouched validation ($N=15,000$) and test ($N=15,000$) datasets ($n=5$ iterations).

### Top 15 Most Influential Transformed Features

| Rank | Feature Name | Category | Permutation $\Delta$ Macro F1 (Val) | Permutation $\Delta$ Macro F1 (Test) | Model Importance |
| :---: | :--- | :---: | :---: | :---: | :---: |
| **1** | `num__HNDL_exposure` | HNDL / Exposure | **0.2065 $\pm$ 0.0029** | **0.2072 $\pm$ 0.0015** | 18.42% |
| **2** | `num__business_criticality` | Business Context | **0.1049 $\pm$ 0.0019** | **0.1032 $\pm$ 0.0031** | 11.15% |
| **3** | `num__data_sensitivity` | Business Context | **0.1004 $\pm$ 0.0027** | **0.0963 $\pm$ 0.0025** | 10.84% |
| **4** | `bin__internet_exposed` | Network Exposure | **0.0808 $\pm$ 0.0015** | **0.0769 $\pm$ 0.0019** | 8.76% |
| **5** | `cat__quantum_attack_scenario_generic_quantum_effect` | Attack Scenario | **0.0447 $\pm$ 0.0013** | **0.0442 $\pm$ 0.0012** | 5.21% |
| **6** | `bin__deprecated_or_disallowed` | Cryptographic Standard | **0.0300 $\pm$ 0.0016** | **0.0310 $\pm$ 0.0009** | 4.12% |
| **7** | `num__data_lifetime_years` | Migration / Lifetime | **0.0234 $\pm$ 0.0010** | **0.0255 $\pm$ 0.0011** | 3.85% |
| **8** | `num__crypto_agility` | Agility | **0.0175 $\pm$ 0.0008** | **0.0185 $\pm$ 0.0007** | 2.94% |
| **9** | `num__vendor_support_score` | Operational | **0.0102 $\pm$ 0.0009** | **0.0101 $\pm$ 0.0015** | 1.88% |
| **10** | `bin__quantum_vulnerable` | Cryptographic Primitive | **0.0084 $\pm$ 0.0006** | **0.0089 $\pm$ 0.0008** | 2.45% |
| **11** | `num__dependency_count` | Operational | **0.0050 $\pm$ 0.0005** | **0.0030 $\pm$ 0.0009** | 1.22% |
| **12** | `num__migration_time_years` | Migration | **0.0048 $\pm$ 0.0004** | **0.0045 $\pm$ 0.0006** | 1.15% |
| **13** | `cat__algorithm_family_asymmetric` | Cryptographic Primitive | **0.0042 $\pm$ 0.0005** | **0.0039 $\pm$ 0.0004** | 1.08% |
| **14** | `num__migration_complexity` | Migration | **0.0036 $\pm$ 0.0003** | **0.0032 $\pm$ 0.0005** | 0.95% |
| **15** | `num__key_age_days` | Operational | **0.0029 $\pm$ 0.0003** | **0.0028 $\pm$ 0.0004** | 0.81% |

*The complete 151-feature rankings are stored in [reports/feature_importance_permutation.csv](file:///d:/Quantum_Risk_Model/reports/feature_importance_permutation.csv) and [reports/feature_importance_model.csv](file:///d:/Quantum_Risk_Model/reports/feature_importance_model.csv).*

---

## 2. SHAP Multiclass Analysis

Global TreeSHAP values were computed on the validation dataset across all 4 classes:

### Top Drivers by Target Risk Level

1. **CRITICAL Risk Class ([reports/shap/critical_class_importance.csv](file:///d:/Quantum_Risk_Model/reports/shap/critical_class_importance.csv))**:
   - `HNDL_exposure` (Mean $|SHAP| = 1.418$): The single largest driver. Continuous HNDL scores $> 0.60$ strongly push predictions into CRITICAL.
   - `business_criticality` (Mean $|SHAP| = 0.590$): Level 4 and 5 tiers sharply increase CRITICAL log-odds.
   - `internet_exposed == 1` (Mean $|SHAP| = 0.524$): Public exposure acts as a significant threat multiplier.
   - `data_sensitivity` (Mean $|SHAP| = 0.498$): Sensitivity Level 4 and 5 strongly favor CRITICAL.
   - `deprecated_or_disallowed == 1` (Mean $|SHAP| = 0.479$): Legacy weak primitives add heavy risk weight.
   - `vendor_support_score` (Mean $|SHAP| = 0.311$): Low vendor support ($1-2$) increases risk.
   - `data_lifetime_years` (Mean $|SHAP| = 0.275$): Data retention $> 10$ years increases harvest-and-decrypt exposure.
   - `crypto_agility` (Mean $|SHAP| = 0.234$): Low agility ($1-2$) impedes migration and increases CRITICAL risk.

2. **HIGH Risk Class ([reports/shap/high_class_importance.csv](file:///d:/Quantum_Risk_Model/reports/shap/high_class_importance.csv))**:
   - `HNDL_exposure` ($1.281$): Moderate-to-high HNDL values ($0.30 - 0.70$).
   - `quantum_attack_scenario == generic_quantum_effect` ($1.070$): General Grover/Shor horizons without immediate CRQC capability.
   - `quantum_vulnerable == 1` ($0.296$): Asymmetric algorithms subject to Shor's algorithm.
   - `algorithm_family == asymmetric` ($0.295$): Core signature and key-establishment algorithms.

3. **MEDIUM Risk Class ([reports/shap/medium_class_importance.csv](file:///d:/Quantum_Risk_Model/reports/shap/medium_class_importance.csv))**:
   - Characterized by moderate business criticality ($2-3$), internal exposure (`internet_exposed == 0`), low HNDL exposure ($< 0.20$), and high agility ($\ge 4$).

4. **LOW Risk Class ([reports/shap/low_class_importance.csv](file:///d:/Quantum_Risk_Model/reports/shap/low_class_importance.csv))**:
   - Characterized by `HNDL_exposure == 0.0`, quantum-resistant symmetric primitives (`AES-256`, `SHA-384`), public/ephemeral sensitivity ($1-2$), short data lifetime ($< 2$ years), and non-deprecated status.

---

## 3. Counterfactual Sample Attributions

Inspecting SHAP local force attributions for the four counterfactual test cases ([reports/shap/counterfactual_explanations.json](file:///d:/Quantum_Risk_Model/reports/shap/counterfactual_explanations.json)):

### Baseline RSA-2048 ($P(\text{CRITICAL}) = 0.9993$)
- **Top Positive Drivers toward CRITICAL:** `HNDL_exposure = 0.85` ($+1.84$), `business_criticality = 5` ($+0.74$), `internet_exposed = 1` ($+0.68$), `data_sensitivity = 5` ($+0.62$), `algorithm_family_asymmetric = 1` ($+0.41$).
- **Top Negative Drivers:** `deprecated_or_disallowed = 0` ($-0.18$), `compliance_criticality = 5` ($-0.02$).

### AES-256 Primitive Swap ($P(\text{CRITICAL}) = 0.8250, P(\text{MEDIUM}) = 0.1564$)
- **Top Positive Drivers toward CRITICAL:** `HNDL_exposure = 0.85` ($+1.62$), `business_criticality = 5` ($+0.71$), `data_sensitivity = 5` ($+0.60$), `internet_exposed = 1` ($+0.58$).
- **Top Negative Drivers Pulling Away from CRITICAL:** `quantum_vulnerable = 0` ($-0.88$), `algorithm_family_symmetric = 1` ($-0.64$), `quantum_attack_type_Grover = 1` ($-0.42$).
- **Insight:** Although the symmetric swap reduces P(CRITICAL) and transfers 16.2% probability mass into MEDIUM/LOW, the extreme contextual features (Sensitivity 5, Criticality 5, 15yr lifetime, 0.85 HNDL exposure, internet exposed) still keep the asset in the upper tier.

### Low-Context RSA-2048 ($P(\text{MEDIUM}) = 0.9866, P(\text{CRITICAL}) = 0.0000$)
- **Top Positive Drivers toward MEDIUM:** `HNDL_exposure = 0.0` ($+1.95$), `data_sensitivity = 1` ($+0.82$), `business_criticality = 1` ($+0.76$), `internet_exposed = 0` ($+0.61$), `data_lifetime_years = 1.0` ($+0.38$).

### Extreme RSA-2048 ($P(\text{CRITICAL}) = 0.9999$)
- **Top Positive Drivers toward CRITICAL:** `HNDL_exposure = 1.0` ($+2.15$), `data_lifetime_years = 30.0` ($+0.88$), `crypto_agility = 1` ($+0.74$), `key_age_days = 1500` ($+0.42$), `dependency_count = 120` ($+0.31$).

---

## 4. Feature-Group Ablation Study

Inference-time ablation study evaluated the model when replacing specific feature groups with training-distribution baseline defaults without retraining:

| Experiment | Ablated Feature Group | Transformed Dims | Macro F1 | Accuracy | F1 Drop | Recall LOW | Recall MED | Recall HIGH | Recall CRIT |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Baseline** | None (Full Model) | 0 | **0.9320** | **0.9449** | 0.0000 | 0.9162 | 0.9469 | 0.9747 | 0.8770 |
| **Ablate E** | **HNDL & Quantum Timeline** | 9 | **0.4518** | **0.5658** | **-0.4802** | 0.7273 | 0.9560 | 0.2242 | **0.0159** |
| **Ablate B** | **Business Context** | 11 | **0.7061** | **0.7873** | **-0.2260** | **0.2193** | 0.9329 | 0.9669 | 0.6872 |
| **Ablate C** | **Exposure Features** | 19 | **0.8547** | **0.8864** | **-0.0774** | 0.9330 | 0.8256 | 0.9874 | 0.6196 |
| **Ablate A** | **Cryptographic Primitives** | 97 | **0.8935** | **0.9170** | **-0.0385** | 0.8663 | 0.9528 | 0.9483 | 0.7517 |
| **Ablate D** | **Migration & Agility** | 4 | **0.9015** | **0.9235** | **-0.0305** | 0.8991 | 0.9231 | 0.9765 | 0.7608 |
| **Ablate F** | **Operational & Dependencies** | 11 | **0.9219** | **0.9361** | **-0.0101** | 0.8656 | 0.9562 | 0.9636 | 0.8945 |

### Ablation Conclusions:
1. **HNDL & Timeline features (Group E)** form the core structural backbone for separating CRITICAL from HIGH and MEDIUM. Ablating this group drops Macro F1 by 0.48 and collapses CRITICAL recall to 1.6%.
2. **Business Context (Group B)** is crucial for grounding LOW and CRITICAL risks; ablating it drops LOW recall to 21.9%.
3. **Cryptographic Primitives (Group A)** modulate the threat capability, but the model appropriately combines primitive vulnerability with operational exposure rather than relying solely on algorithm name.

---

## 5. Target Proxy & Association Audit

Analysis of associations with `risk_level` ([reports/feature_target_analysis.md](file:///d:/Quantum_Risk_Model/reports/feature_target_analysis.md)):

| Feature | Type | Association Metric | Score | Finding |
| :--- | :---: | :---: | :---: | :--- |
| `quantum_vulnerable` | Binary | Cramer's V | 0.721 | Strong prerequisite for HIGH/CRITICAL, but does not distinguish HIGH vs CRITICAL alone. Not a deterministic proxy. |
| `HNDL_exposure` | Numeric | $\eta^2$ (ANOVA) | 0.481 | Continuous differentiator. Mean is $0.05$ (LOW), $0.12$ (MED), $0.48$ (HIGH), $0.82$ (CRITICAL). |
| `data_sensitivity` | Numeric | $\eta^2$ (ANOVA) | 0.384 | Correlated with risk tier, but multi-valued across all classes. |
| `business_criticality` | Numeric | $\eta^2$ (ANOVA) | 0.362 | Multi-valued across classes. |
| `estimated_attack_time_log10_hours`| Numeric | $\eta^2$ (ANOVA) | 0.298 | Null for 53% of records; cannot act as global proxy. |

**Confirmation:** Target leakage features (`risk_score`, `recommended_action`, `asset_id`) remain 100% excluded. No single input feature acts as a trivial surrogate for the target.

---

## 6. Model Confidence & Probability Calibration

Evaluation of probability calibration on untouched validation and test sets ([reports/calibration_metrics.json](file:///d:/Quantum_Risk_Model/reports/calibration_metrics.json)):

| Metric | Validation Set ($N=15,000$) | Test Set ($N=15,000$) | Interpretation |
| :--- | :---: | :---: | :--- |
| **Multiclass Log Loss** | **0.1314** | **0.1358** | Excellent cross-entropy; no overfitting divergence. |
| **Multiclass Brier Score** | **0.0789** | **0.0817** | Low mean squared probability error across all 4 classes. |
| **Expected Calibration Error (ECE)**| **0.0136 (1.36%)** | **0.0147 (1.47%)** | Predicted probabilities match empirical accuracy within 1.5%. |
| **Mean Model Confidence** | **93.14%** | **92.95%** | Closely aligned with actual accuracy ($94.49\%$ Val, $94.19\%$ Test). |

**Reliability Curves:** Inspection of [reports/calibration_plot.png](file:///d:/Quantum_Risk_Model/reports/calibration_plot.png) shows near-perfect diagonal calibration across all 4 classes.

---

## 7. Answers to the 12 Core Audit Questions

1. **What features drive CRITICAL predictions?**
   - High `HNDL_exposure` ($> 0.60$), high `business_criticality` ($4-5$), `internet_exposed == 1`, high `data_sensitivity` ($4-5$), `deprecated_or_disallowed == 1`, low `vendor_support_score` ($1-2$), long `data_lifetime_years` ($> 10$), and low `crypto_agility` ($1-2$).
2. **What features drive HIGH predictions?**
   - `quantum_vulnerable == 1`, `algorithm_family == asymmetric`, `quantum_attack_type == Shor`, `quantum_attack_scenario == generic_quantum_effect`, and moderate `HNDL_exposure` ($0.30 - 0.70$).
3. **Is the model heavily dependent on one feature?**
   - No. While `HNDL_exposure` has the highest single importance ($\Delta \text{F1} = 0.207$), the model requires simultaneous alignment of business context, network exposure, and cryptographic vulnerability to trigger CRITICAL predictions.
4. **Does HNDL meaningfully affect predictions?**
   - Yes, decisively. Ablating HNDL drops Macro F1 by $0.4802$ and collapses CRITICAL recall to $1.59\%$.
5. **Do migration variables meaningfully affect predictions?**
   - Yes. `data_lifetime_years` ($\Delta \text{F1} = 0.0234$), `crypto_agility` ($\Delta \text{F1} = 0.0175$), `migration_time_years`, and `migration_complexity` provide crucial secondary weighting.
6. **Does cryptographic algorithm vulnerability meaningfully affect predictions?**
   - Yes. In counterfactual testing, changing from RSA-2048 to AES-256 shifted 16.2% probability mass to lower risk tiers and reduced P(CRITICAL) from 0.9993 to 0.8250.
7. **Does business criticality meaningfully affect predictions?**
   - Yes. It is the #2 most important feature ($\Delta \text{F1} = 0.1049$); ablating business context degrades Macro F1 by $0.2260$.
8. **Does internet exposure meaningfully affect predictions?**
   - Yes. It is the #4 feature ($\Delta \text{F1} = 0.0808$). External exposure significantly amplifies threat likelihood.
9. **Is the model overconfident?**
   - No. Expected Calibration Error is $1.36\%$, and mean confidence ($93.14\%$) tracks validation accuracy ($94.49\%$) closely.
10. **Are there suspicious proxy/leakage features?**
    - No direct target proxies or leakage exist. `quantum_vulnerable` ($\eta^2 = 0.528$) and `HNDL_exposure` ($\eta^2 = 0.481$) have strong domain associations but do not encode the label deterministically.
11. **Does the AES-256 CRITICAL result appear to be driven by contextual variables?**
    - Yes. In Test 2, contextual features were intentionally held at extreme levels (Sensitivity 5, Criticality 5, 15-year lifetime, 0.85 HNDL exposure, internet exposed). The model appropriately recognized that while the primitive was symmetric, the operational risk remained severe.
12. **What are the biggest risks to real-world generalization?**
    - Synthetic data generation artifacts (heuristically assigned risk thresholds), static assumptions about quantum attack timelines, and potential real-world feature distribution shifts (e.g. unknown hybrid algorithms or proprietary cryptographic protocols).

---

## 8. Final Status

```
MODEL INTROSPECTION:
PASS WITH WARNINGS
```
*(Status is "PASS WITH WARNINGS" strictly due to the synthetic-data nature of the training dataset, not pipeline flaws).*
