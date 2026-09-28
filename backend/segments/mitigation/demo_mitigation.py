"""Demo & Verification script for the Mitigation Segment.

Loads the completed ML risk report (or CBOM bundle) and runs the MitigationAgent
to generate a full, prioritized PQC migration plan with:
- Wave 1, Wave 2, and Wave 3 allocations
- NIST FIPS 203/204/205 PQC algorithm replacements
- Blast radius & service concentration analysis
- Actionable suggestions & AI code replacements
"""

import json
import os
import sys
from pathlib import Path

# Add backend root to path
backend_dir = Path(__file__).resolve().parent.parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from segments.mitigation.mitigation_agent import MitigationAgent


def main():
    print("=" * 80)
    print("ECDAT MITIGATION SEGMENT - PQC MIGRATION & REMEDIATION RUNNER")
    print("=" * 80)

    # Path to final ML risk report
    report_path = backend_dir / "ecdat_final_risk_report.json"
    if not report_path.exists():
        report_path = backend_dir / "segments" / "ml" / "ecdat_final_risk_report.json"

    if report_path.exists():
        print(f"[*] Ingesting ML Final Risk Report from: {report_path.name}")
        with open(report_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
    else:
        print("[!] Final risk report not found, creating synthetic multi-service crypto bundle...")
        bundle = {
            "application": "ECDAT Target Systems",
            "risk_context": {
                "network": {"publicly_accessible": True, "internet_facing": True},
                "data": {"types": ["PII", "Financial", "SessionTokens"]},
            },
            "assets": [
                {
                    "id": "ASSET-001",
                    "algorithm": "RSA-2048",
                    "algorithm_category": "PUBLIC_KEY",
                    "quantum_vulnerable": True,
                    "migration_priority": "URGENT",
                    "hndl_risk": "HIGH",
                    "service": "auth-service",
                    "cbom_asset": {
                        "location": {"file": "apps/auth-service/jwt_signer.py", "line": 42},
                        "evidence": "jwt.encode(payload, rsa_private_key, algorithm='RS256')",
                    },
                },
                {
                    "id": "ASSET-002",
                    "algorithm": "ECDSA-P256",
                    "algorithm_category": "PUBLIC_KEY",
                    "quantum_vulnerable": True,
                    "migration_priority": "HIGH",
                    "hndl_risk": "MEDIUM",
                    "service": "payment-gateway",
                    "cbom_asset": {
                        "location": {"file": "apps/payment-gateway/signer.py", "line": 88},
                        "evidence": "ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)",
                    },
                },
                {
                    "id": "ASSET-003",
                    "algorithm": "AES-128",
                    "algorithm_category": "SYMMETRIC",
                    "quantum_vulnerable": False,
                    "migration_priority": "MEDIUM",
                    "hndl_risk": "LOW",
                    "service": "storage-service",
                    "cbom_asset": {
                        "location": {"file": "apps/storage-service/db_encrypt.py", "line": 15},
                        "evidence": "Cipher(algorithms.AES(key_128), modes.CBC(iv))",
                    },
                },
                {
                    "id": "ASSET-004",
                    "algorithm": "SHA-1",
                    "algorithm_category": "HASH",
                    "quantum_vulnerable": False,
                    "migration_priority": "LOW",
                    "hndl_risk": "LOW",
                    "service": "legacy-integrity",
                    "cbom_asset": {
                        "location": {"file": "apps/legacy/checksum.py", "line": 10},
                        "evidence": "hashlib.sha1(data).hexdigest()",
                    },
                },
            ],
        }

    print("[*] Initializing MitigationAgent (Deterministic Rules + AI Narrator)...")
    agent = MitigationAgent(use_llm=True)

    print("[*] Generating remediation and migration plan document...")
    plan_doc = agent.generate(bundle)

    # Print Summary & Stats
    stats = plan_doc.get("summary", {})
    print("\n" + "-" * 50)
    print("PLAN SUMMARY & WAVE BREAKDOWN:")
    print("-" * 50)
    print(f"  • Total Crypto Assets Evaluated: {stats.get('assets', 0)}")
    print(f"  • Post-Quantum Vulnerable:       {stats.get('quantum_vulnerable', 0)}")
    print(f"  • Urgent Migration Priority:     {stats.get('urgent', 0)}")
    print(f"  • HNDL-Exposed (Harvest-Now):    {stats.get('hndl_exposed', 0)}")
    print(f"  • Wave 1 (0-3 Months / Urgent):  {stats.get('wave1', 0)} assets")
    print(f"  • Wave 2 (3-12 Months / PQC):    {stats.get('wave2', 0)} assets")
    print(f"  • Wave 3 (12-24 Months / Harden):{stats.get('wave3', 0)} assets")
    print(f"  • Estimated Migration Duration:  {stats.get('effort_estimate_quarters', 0)} quarter(s)")

    print("\n" + "-" * 50)
    print("EXECUTIVE MITIGATION SUMMARY:")
    print("-" * 50)
    print(plan_doc.get("executive_summary", "N/A"))

    print("\n" + "-" * 50)
    print("QUANTUM RISK NARRATIVE:")
    print("-" * 50)
    print(plan_doc.get("quantum_risk_narrative", "N/A"))

    print("\n" + "-" * 50)
    print("SAMPLE ASSET MITIGATION MAPPINGS (First 4 rows):")
    print("-" * 50)
    for row in plan_doc.get("rows", [])[:4]:
        print(f"  [{row.get('asset_id') or row.get('id')}] {row.get('algorithm')} ({row.get('service')})")
        print(f"    - Migration Wave:       Wave {row.get('migration_wave')}")
        print(f"    - Target PQC Standard:  {row.get('migration_impact', {}).get('replacement')}")
        print(f"    - Effort / Impact:      {row.get('migration_impact', {}).get('effort')} / {row.get('migration_impact', {}).get('impact')}")
        print(f"    - Blast Radius:         {row.get('blast_radius', {}).get('severity')} severity ({row.get('blast_radius', {}).get('exposure')} surface)")
        suggs = row.get("suggestions", [])
        if suggs:
            print(f"    - Key Action:           {suggs[0]}")
        print()

    # Save output to JSON
    output_path = Path(__file__).resolve().parent / "mitigation_plan_output.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(plan_doc, f, indent=2, default=str)

    print(f"[+] Full Mitigation Plan saved to: {output_path}")
    print("=" * 80)
    print("MITIGATION PLAN GENERATION COMPLETE!")
    print("=" * 80)


if __name__ == "__main__":
    main()
