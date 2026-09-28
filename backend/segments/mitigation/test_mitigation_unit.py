"""Unit and integration tests for the Mitigation Segment.

Tests:
- Deterministic rules and NIST PQC replacement mappings
- Service blast radius and multi-service concentration
- Priority Wave assignments (Wave 1, Wave 2, Wave 3)
- Actionable suggestions and recommendations
- MitigationAgent document assembly and LLM response cleaning
- Robust ingestion of final risk reports (ecdat_final_risk_report.json)
"""

import json
import os
import sys
from pathlib import Path
import unittest

backend_dir = Path(__file__).resolve().parent.parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from segments.mitigation.mitigation_agent import rules
from segments.mitigation.mitigation_agent.llm_provider import clean_narrative_json
from segments.mitigation.mitigation_agent.mitigation_agent import MitigationAgent, normalize_bundle


class TestMitigationRules(unittest.TestCase):
    """Test deterministic PQC rules and impact analysis."""

    def test_service_for_location_paths(self):
        self.assertEqual(
            rules.service_for_location(r"C:\workspace\apps\payment-service\app.py"),
            "payment-service",
        )
        self.assertEqual(
            rules.service_for_location("repo/src/auth-service/jwt_tokens.py"),
            "auth-service",
        )
        self.assertEqual(rules.service_for_location(None), "unknown")
        self.assertEqual(rules.service_for_location(""), "unknown")

    def test_pqc_replacement_mapping(self):
        # RSA-2048
        impact = rules.compute_migration_impact({"algorithm": "RSA-2048", "algorithm_category": "PUBLIC_KEY"})
        self.assertIn("ML-KEM-768", impact["replacement"])
        self.assertEqual(impact["effort"], "HIGH")

        # RSA-4096
        impact4k = rules.compute_migration_impact({"algorithm": "RSA-4096", "algorithm_category": "PUBLIC_KEY"})
        self.assertIn("ML-KEM-1024", impact4k["replacement"])

        # ECDSA-P256
        impact_ecdsa = rules.compute_migration_impact({"algorithm": "ECDSA-P256", "algorithm_category": "PUBLIC_KEY"})
        self.assertIn("ML-DSA-65", impact_ecdsa["replacement"])

        # Hybrid X25519
        impact_x25519 = rules.compute_migration_impact({"algorithm": "X25519", "algorithm_category": "PUBLIC_KEY"})
        self.assertIn("Hybrid X25519MLKEM768", impact_x25519["replacement"])

        # Symmetric AES-128 to AES-256
        impact_aes = rules.compute_migration_impact({"algorithm": "AES-128", "algorithm_category": "SYMMETRIC"})
        self.assertEqual(impact_aes["replacement"], "AES-256 (GCM)")

        # Broken MD5 to SHA-256 / SHA-3
        impact_md5 = rules.compute_migration_impact({"algorithm": "MD5", "algorithm_category": "HASH"})
        self.assertEqual(impact_md5["replacement"], "SHA-256 / SHA-3")

    def test_blast_radius_calculation(self):
        bundle = {
            "risk_context": {"network": {"publicly_accessible": True}},
            "assets": [],
        }
        blast = rules.compute_blast_radius(
            {
                "id": "A1",
                "algorithm": "RSA-2048",
                "algorithm_category": "PUBLIC_KEY",
                "quantum_vulnerable": True,
                "migration_priority": "URGENT",
                "service": "auth-service",
            },
            bundle,
        )
        self.assertEqual(blast["severity"], "CRITICAL")
        self.assertEqual(blast["exposure"], "public")

    def test_wave_prioritization(self):
        # Urgent & Quantum Vulnerable -> Wave 1
        wave1 = rules.migration_wave_for(
            {
                "migration_priority": "URGENT",
                "algorithm_category": "PUBLIC_KEY",
                "quantum_vulnerable": True,
            },
            {"severity": "CRITICAL"},
        )
        self.assertEqual(wave1, 1)

        # High Priority -> Wave 2
        wave2 = rules.migration_wave_for(
            {
                "migration_priority": "HIGH",
                "algorithm_category": "PUBLIC_KEY",
                "quantum_vulnerable": False,
            },
            {"severity": "HIGH"},
        )
        self.assertEqual(wave2, 2)

        # Low Priority / Symmetric -> Wave 3
        wave3 = rules.migration_wave_for(
            {
                "migration_priority": "LOW",
                "algorithm_category": "SYMMETRIC",
                "quantum_vulnerable": False,
            },
            {"severity": "LOW"},
        )
        self.assertEqual(wave3, 3)

    def test_clean_narrative_json_parsing(self):
        raw = '```json\n{"executive_summary": "PQC remediation plan prepared.", "strategic_recommendations": [{"title": "Rotate keys", "timeline": "Q1"}]}\n```'
        cleaned = clean_narrative_json(raw)
        self.assertIsNotNone(cleaned)
        self.assertEqual(cleaned["executive_summary"], "PQC remediation plan prepared.")
        self.assertEqual(len(cleaned["strategic_recommendations"]), 1)


class TestMitigationAgentEndToEnd(unittest.TestCase):
    """Test full document generation from bundles and ML risk reports."""

    def test_generate_from_bundle(self):
        bundle = {
            "application": "Test Crypto Suite",
            "risk_context": {"network": {"publicly_accessible": False}},
            "assets": [
                {
                    "id": "N1",
                    "algorithm": "RSA-2048",
                    "algorithm_category": "PUBLIC_KEY",
                    "quantum_vulnerable": True,
                    "migration_priority": "URGENT",
                    "service": "auth-service",
                },
                {
                    "id": "N2",
                    "algorithm": "AES-256",
                    "algorithm_category": "SYMMETRIC",
                    "quantum_vulnerable": False,
                    "migration_priority": "LOW",
                    "service": "db-service",
                },
            ],
        }
        agent = MitigationAgent(use_llm=False)
        doc = agent.generate(bundle)

        self.assertIn("summary", doc)
        self.assertIn("waves", doc)
        self.assertIn("rows", doc)
        self.assertEqual(doc["summary"]["assets"], 2)
        self.assertEqual(doc["summary"]["quantum_vulnerable"], 1)
        self.assertEqual(doc["summary"]["wave1"], 1)
        self.assertEqual(doc["summary"]["wave3"], 1)

    def test_normalize_bundle_from_final_risk_report(self):
        report = {
            "report_title": "Enterprise Risk Report",
            "portfolio_stats": {"total_assets": 1},
            "asset_reports": [
                {
                    "asset_id": "DISC-99",
                    "algorithm": "ECDSA",
                    "pqc_status": "CLASSICAL_VULNERABLE",
                    "overall_quantum_risk_tier": "HIGH",
                    "urgency_tier": "HIGH",
                }
            ],
        }
        normalized = normalize_bundle(report)
        self.assertIn("assets", normalized)
        self.assertEqual(len(normalized["assets"]), 1)
        self.assertEqual(normalized["assets"][0]["algorithm"], "ECDSA")
        self.assertTrue(normalized["assets"][0]["quantum_vulnerable"])


if __name__ == "__main__":
    unittest.main()
