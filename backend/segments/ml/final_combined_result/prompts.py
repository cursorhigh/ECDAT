"""
Prompts and Templates for Final Combined Result Synthesis (prompts.py)

Directs Google Gemini AI to synthesize outputs from:
1. CatBoost ML Quantum Risk Model (probabilities, feature importances)
2. HNDL Timeline Engine (harvestability, susceptibility, shelf-life factor)
3. Mosca Theorem Agent (X + Y > Z deficit, start deadlines)

Strictly requires grounding and explicit source attributions without hallucinating metrics.
"""

FINAL_REPORT_SYNTHESIS_SYSTEM_PROMPT = """
You are the Chief Cryptographic Risk Officer and Post-Quantum Risk Intelligence Engine for ECDAT (Enterprise Cryptographic Discovery & Assessment Tool).
Your task is to synthesize the unified Post-Quantum Risk Report for enterprise software cryptographic assets.

You are provided with quantitative evidence from three distinct analysis pillars:
1. ML_RISK: The 37-feature CatBoost Quantum Risk Model (Risk Tier, Confidence, Class Probabilities, Top Influencing Features / SHAP).
2. HNDL_ENGINE: Harvest-Now-Decrypt-Later Timeline Engine (Cryptographic Susceptibility, Harvestability Score, Data Shelf Life vs. CRQC Horizon, Future Decryption Risk).
3. MOSCA_THEOREM: Michele Mosca's Inequality (X + Y > Z, Migration Duration X, Shelf-Life Y, CRQC Horizon Z, Timeline Deficit ΔM, Migration Start Deadline).

STRICT SYNTHESIS RULES:
1. Grounding: All statements, numbers, and conclusions MUST be grounded directly in the provided inputs. Never invent key sizes, deadlines, or probabilities.
2. Source Attribution: Clearly cite where conclusions originate:
   - Cite [ML Risk Model] for risk tier classifications, confidence scores, and SHAP feature drivers.
   - Cite [HNDL Engine] for harvestability, lack of forward secrecy, and long-lived data exposure before CRQC.
   - Cite [Mosca Theorem] for migration time X, shelf-life Y, deficit ΔM, and deadline year T_deadline.
3. Unified Scoring: Produce an overall unified risk score from 0.0 (Safe) to 100.0 (Critical Threat) and an overall urgency tier.
4. Actionability: Provide concrete, prescriptive recommendations (e.g. migrate RSA to ML-KEM-768 / FIPS 203, enable Perfect Forward Secrecy).
5. Output Format: Respond ONLY with a valid JSON object matching the requested schema. Do not enclose in markdown blocks unless returning raw JSON.
"""

ASSET_SYNTHESIS_USER_PROMPT_TEMPLATE = """
Synthesize the final risk report for the following cryptographic asset:

Asset ID: {asset_id}
Algorithm: {algorithm}
Family: {family}
Function / Role: {crypto_role}
Parameters: {parameters}

=== Pillar 1: ML Quantum Risk Model ===
{ml_risk_json}

=== Pillar 2: HNDL Timeline Engine ===
{hndl_json}

=== Pillar 3: Mosca Theorem Inequality ===
{mosca_json}

=== Operational Context ===
{operational_context_json}

Respond with a JSON object adhering to this schema:
{{
  "asset_id": "{asset_id}",
  "algorithm": "{algorithm}",
  "overall_quantum_risk_tier": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NEGLIGIBLE",
  "unified_risk_score": float (0.0 - 100.0),
  "urgency_tier": "IMMEDIATE" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NEGLIGIBLE",
  "primary_risk_driver": "Short summary of main risk factor",
  "executive_narrative": "Crisp executive summary paragraph with embedded citations [ML Risk], [HNDL], [Mosca]",
  "attributions": [
    {{
      "pillar": "ML_RISK" | "HNDL_ENGINE" | "MOSCA_THEOREM" | "CBOM_CATALOG",
      "metric_name": "string",
      "value": "string or number",
      "source_detail": "Explanation of how this metric influenced the finding"
    }}
  ],
  "recommended_action": "Specific cryptographic migration step"
}}
"""

PORTFOLIO_SYNTHESIS_USER_PROMPT_TEMPLATE = """
Synthesize the global application-level Post-Quantum Cryptographic Risk Executive Report across {total_assets} cryptographic assets.

Portfolio Statistics:
- Total Assets: {total_assets}
- Critical Risk Assets: {critical_count}
- High Risk Assets: {high_count}
- HNDL Exposed Assets: {hndl_count}
- Mosca Deficit Assets: {mosca_count}
- Overdue Migration Assets: {overdue_count}
- Earliest Migration Start Deadline: {earliest_deadline}

Asset Summaries:
{assets_summary_json}

Respond with a JSON object adhering to this schema:
{{
  "report_title": "ECDAT Enterprise Post-Quantum Cryptographic Risk Report",
  "executive_summary": "Comprehensive executive briefing detailing application quantum vulnerability posture, exposure to Harvest Now Decrypt Later, and Mosca migration timeline deficits.",
  "key_findings": [
    "High impact bullet 1 citing specific algorithms and metrics",
    "High impact bullet 2 citing HNDL / Mosca timelines",
    "High impact bullet 3 citing ML confidence and migration urgency"
  ],
  "source_attribution_summary": {{
    "ML_RISK": "Summary of ML CatBoost contributions across the portfolio",
    "HNDL_ENGINE": "Summary of HNDL exposure contributions",
    "MOSCA_THEOREM": "Summary of Mosca migration timeline deficit contributions"
  }}
}}
"""
