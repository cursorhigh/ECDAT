"""Test script for HNDL & Mosca Simulation Engine."""

import sys
from pathlib import Path
import json

# Add project root to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))

import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
django.setup()

from discovery.risk_engine import simulate_full_hndl_risk, MoscaCalculator, HNDLThreatAnalyzer
from discovery.scanners.demo import generate_enterprise_demo_findings

def test_simulation():
    # User Input 1
    input_1 = {
        "asset_id": "crypto-rsa-001",
        "algorithm": {
            "family": "RSA",
            "name": "RSA"
        },
        "parameters": {
            "key_size": 2048
        },
        "purpose": [
            "key_establishment"
        ]
    }

    # User Input 2
    input_2 = {
        "data_context": {
            "sensitivity": "CRITICAL",
            "data_lifetime_years": 20
        },
        "network_context": {
            "internet_exposed": True,
            "collectable": True
        }
    }

    result = simulate_full_hndl_risk(input_1, input_2)

    print("=== HNDL & Mosca Simulation Output ===")
    print(json.dumps(result, indent=2))

    # Assertions
    assert result["mosca_inequality"]["X_shelf_life_years"] == 20
    assert result["mosca_inequality"]["total_exposure_window_years"] == 25
    assert result["mosca_inequality"]["quantum_deficit_years"] == 15
    assert result["mosca_inequality"]["in_quantum_deficit"] is True
    assert result["hndl_analysis"]["hndl_threat_detected"] is True
    assert result["hndl_analysis"]["hndl_risk_level"] == "CRITICAL"
    print("\nSUCCESS: All simulation assertions passed!")

    # Test enterprise findings generation
    findings = generate_enterprise_demo_findings(full_distribution=True)
    print(f"\nGenerated Enterprise Demo Findings Count: {len(findings)}")
    
    counts = {}
    for f in findings:
        fam = f["algorithm"]
        counts[fam] = counts.get(fam, 0) + 1
        
    print("Algorithm breakdown in demo dataset:")
    for algo, count in sorted(counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {algo}: {count}")

if __name__ == "__main__":
    test_simulation()
