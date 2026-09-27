"""Tests for the mitigation rules engine, agent suite and API endpoints."""

import os
from unittest import mock

from django.test import Client, TestCase, override_settings

from segments.ml.analysis.models import AnalysisRun
from segments.scraping.discovery.models import ScanJob
from segments.mitigation.mitigation.models import MitigationPlan
from segments.mitigation.mitigation.planner import generate_plan, trigger_mitigation
from segments.mitigation.mitigation_agent import MitigationAgent
from segments.mitigation.mitigation_agent import rules
from segments.mitigation.mitigation_agent.llm_provider import clean_narrative_json
from segments.mitigation.mitigation_agent.prompts import build_mitigation_prompt

_FORCE_FALLBACK_PROVIDERS = {
    "GEMINI_API_KEY_CBOM": "",
    "GEMINI_API_KEY_RISK": "",
    "GEMINI_API_KEY_HNDL": "",
    "GEMINI_API_KEY_MOSCA": "",
    "GEMINI_API_KEY_MITIGATION": "",
    "GEMINI_API_KEY": "",
}


class RulesTests(TestCase):
    """Pure deterministic rule engines."""

    def test_service_for_location_windows_and_posix(self):
        self.assertEqual(
            rules.service_for_location(
                r"C:\Users\x\enterprise-scan-target\apps\payment-service\app.py"
            ),
            "payment-service",
        )
        self.assertEqual(
            rules.service_for_location("repo/src/auth-service/keys.py"),
            "auth-service",
        )
        self.assertEqual(rules.service_for_location(None), "unknown")
        self.assertEqual(rules.service_for_location(""), "unknown")

    def test_replacement_map_rsa_to_mlkem_ml_dsa(self):
        impact = rules.compute_migration_impact(
            {"algorithm": "RSA", "algorithm_category": "PUBLIC_KEY"}
        )
        self.assertEqual(impact["replacement"], "ML-KEM-1024 / ML-DSA-87")
        self.assertEqual(impact["effort"], "HIGH")
        self.assertEqual(impact["impact"], "HIGH")

    def test_symmetric_aes_stays_aes256(self):
        impact = rules.compute_migration_impact(
            {"algorithm": "AES", "algorithm_category": "SYMMETRIC"}
        )
        self.assertEqual(impact["replacement"], "AES-256 (GCM)")
        self.assertEqual(impact["effort"], "LOW")

    def test_blast_radius_escalates_quantum_vulnerable_public_key(self):
        run_bundle = {
            "risk_context": {"network": {"publicly_accessible": True}},
            "assets": [],
        }
        blast = rules.compute_blast_radius(
            {
                "id": "N1",
                "algorithm": "RSA",
                "algorithm_category": "PUBLIC_KEY",
                "quantum_vulnerable": True,
                "migration_priority": "URGENT",
                "service": "payment-service",
            },
            run_bundle,
        )
        self.assertEqual(blast["severity"], "CRITICAL")
        self.assertEqual(blast["exposure"], "public")

    def test_waves_assign_urgent_to_wave_1(self):
        blast = {"severity": "CRITICAL"}
        wave = rules.migration_wave_for(
            {
                "migration_priority": "URGENT",
                "algorithm_category": "PUBLIC_KEY",
                "quantum_vulnerable": True,
            },
            blast,
        )
        self.assertEqual(wave, 1)

    def test_suggestions_cover_rotation_and_replacement(self):
        suggestions = rules.suggestions_for(
            {
                "algorithm": "RSA",
                "algorithm_category": "PUBLIC_KEY",
                "quantum_vulnerable": True,
                "migration_priority": "URGENT",
                "hndl_risk": "HIGH",
            },
            {"service": "payment-service"},
            {"replacement": "ML-KEM-1024 / ML-DSA-87"},
        )
        joined = " ".join(suggestions).lower()
        self.assertIn("ml-kem", joined)
        self.assertIn("rotate", joined)


def _bundle(rows):
    return {
        "application": "app",
        "repository": {"name": "app"},
        "risk_context": {"network": {"publicly_accessible": True}},
        "assets": rows,
    }


class MitigationAgentTests(TestCase):
    """Agent suite assembles a complete, correctly ordered document."""

    def test_generate_produces_document(self):
        bundle = _bundle(
            [
                {
                    "id": "a1",
                    "asset_id": "N1",
                    "algorithm": "AES",
                    "family": "aes",
                    "algorithm_category": "SYMMETRIC",
                    "classical_security": "HIGH",
                    "overall_risk": "LOW",
                    "migration_priority": "LOW",
                    "quantum_vulnerable": False,
                    "hndl_risk": "",
                    "cbom_asset": {
                        "algorithm": "AES",
                        "location": {"file": "apps/payment-service/app.py"},
                    },
                    "mosca": {},
                    "hndl": {},
                },
                {
                    "id": "a2",
                    "asset_id": "N2",
                    "algorithm": "RSA",
                    "family": "rsa",
                    "algorithm_category": "PUBLIC_KEY",
                    "classical_security": "HIGH",
                    "overall_risk": "HIGH",
                    "migration_priority": "URGENT",
                    "quantum_vulnerable": True,
                    "hndl_risk": "HIGH",
                    "cbom_asset": {
                        "algorithm": "RSA",
                        "location": {"file": "apps/payment-service/keys.py"},
                    },
                    "mosca": {},
                    "hndl": {},
                },
                {
                    "id": "a3",
                    "asset_id": "N3",
                    "algorithm": "SHA256",
                    "family": "hash",
                    "algorithm_category": "HASH",
                    "classical_security": "HIGH",
                    "overall_risk": "LOW",
                    "migration_priority": "LOW",
                    "quantum_vulnerable": False,
                    "hndl_risk": "",
                    "cbom_asset": {
                        "algorithm": "SHA256",
                        "location": {"file": "apps/auth-service/hash.py"},
                    },
                    "mosca": {},
                    "hndl": {},
                },
            ]
        )
        doc = MitigationAgent(use_llm=False).generate(bundle)

        self.assertEqual(doc["summary"]["assets"], 3)
        # RSA (URGENT) must be first, symmetric/hash last.
        self.assertEqual(doc["rows"][0]["algorithm"], "RSA")
        self.assertEqual(doc["rows"][0]["migration_wave"], 1)
        self.assertEqual(doc["rows"][0]["migration_impact"]["replacement"], "ML-KEM-1024 / ML-DSA-87")
        self.assertEqual(doc["summary"]["wave1"], 1)
        self.assertEqual(doc["summary"]["quantum_vulnerable"], 1)
        self.assertEqual(doc["blast_radius"]["affected_services"], 2)
        self.assertFalse(doc["ai_context"]["enhanced"])
        self.assertIn("no LLM", doc["ai_context"]["engine"])
        self.assertTrue(doc["executive_summary"])
        self.assertTrue(doc["quantum_risk_narrative"])
        self.assertEqual(len(doc["waves"]), 3)

    def test_gemini_prompt_and_code_replacement_validation(self):
        doc = MitigationAgent(use_llm=False).generate(
            _bundle(
                [
                    {
                        "id": "a1",
                        "asset_id": "N1",
                        "algorithm": "RSA",
                        "algorithm_category": "PUBLIC_KEY",
                        "migration_priority": "URGENT",
                        "quantum_vulnerable": True,
                        "cbom_asset": {
                            "algorithm": "RSA",
                            "location": {"file": "apps/payment-service/app.py", "line": 12},
                            "evidence": "private_key = rsa.generate_private_key()",
                        },
                    }
                ]
            )
        )
        prompt = build_mitigation_prompt(doc)
        self.assertIn("private_key = rsa.generate_private_key()", prompt)
        self.assertIn("ML-KEM-1024 / ML-DSA-87", prompt)

        valid = clean_narrative_json(
            '{"code_replacements":[{"asset_id":"N1","file":"app.py",'
            '"language":"python","replacement_algorithm":"ML-KEM-1024 / ML-DSA-87",'
            '"vulnerable_code":"old","replacement_code":"new",'
            '"explanation":"replace"}]}',
            doc,
        )
        self.assertEqual(valid["code_replacements"][0]["asset_id"], "N1")

        invalid = clean_narrative_json(
            '{"code_replacements":[{"asset_id":"N1","file":"app.py",'
            '"language":"python","replacement_algorithm":"AES-256 (GCM)",'
            '"vulnerable_code":"old","replacement_code":"new",'
            '"explanation":"replace"}]}',
            doc,
        )
        self.assertIsNone(invalid)


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class MitigationPlannerTests(TestCase):
    """Planner + API endpoints using deterministic fallbacks only."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._env = mock.patch.dict(os.environ, _FORCE_FALLBACK_PROVIDERS, clear=False)
        cls._env.start()

    @classmethod
    def tearDownClass(cls):
        cls._env.stop()
        super().tearDownClass()

    def setUp(self):
        self.client = Client()
        from core.models import WorkSession

        self.session = WorkSession.objects.using("default").create(name="test-session")
        self.client.post(f"/api/session/switch/{self.session.pk}/")

    def _make_completed_run(self):
        job = ScanJob.objects.using("default").create(
            session=self.session,
            source_type="source_code",
            target="work/app",
            mode="actual",
            status="completed",
            findings_count=2,
        )
        run = AnalysisRun.objects.using("default").create(
            scan_job=job,
            session=self.session,
            mode="actual",
            status=AnalysisRun.Status.COMPLETED,
            progress=100,
            repository={"name": "work/app", "url": ""},
            risk_context={"network": {"publicly_accessible": True}},
            executive_summary={
                "rows": [
                    {
                        "asset_id": "N1",
                        "algorithm": "RSA",
                        "algorithm_category": "PUBLIC_KEY",
                        "classical_security": "HIGH",
                        "hndl_risk": "HIGH",
                        "overall_risk": "HIGH",
                        "migration_priority": "URGENT",
                        "quantum_vulnerable": True,
                    },
                    {
                        "asset_id": "N2",
                        "algorithm": "AES",
                        "algorithm_category": "SYMMETRIC",
                        "classical_security": "HIGH",
                        "hndl_risk": "LOW",
                        "overall_risk": "LOW",
                        "migration_priority": "LOW",
                        "quantum_vulnerable": False,
                    },
                ],
                "stats": {"assets": 2, "urgent": 1, "critical": 0, "hndl_applicable": 1},
            },
        )
        return run

    @mock.patch("segments.mitigation.mitigation.planner.threading.Thread")
    def test_trigger_creates_plan_and_dispatches(self, _mock_thread):
        run = self._make_completed_run()
        plan = trigger_mitigation(run, "default")

        self.assertIsInstance(plan, MitigationPlan)
        self.assertEqual(plan.status, MitigationPlan.Status.PENDING)
        self.assertEqual(plan.run_id, run.pk)
        self.assertEqual(_mock_thread.call_count, 1)
        # Idempotent: a follow-up trigger still dispatches but returns same row.
        plan2 = trigger_mitigation(run, "default")
        self.assertEqual(plan2.pk, plan.pk)

    def test_generate_plan_completes_document(self):
        run = self._make_completed_run()
        with mock.patch("segments.mitigation.mitigation.planner.threading.Thread"):
            plan = trigger_mitigation(run, "default")
        result = generate_plan(plan.pk, "actual")

        self.assertEqual(result.status, MitigationPlan.Status.COMPLETE)
        self.assertEqual(result.progress, 100)
        self.assertEqual(result.document["summary"]["assets"], 2)
        self.assertEqual(result.document["rows"][0]["algorithm"], "RSA")
        self.assertEqual(result.document["ai_context"]["enhanced"], False)

    @mock.patch("segments.mitigation.mitigation.planner.threading.Thread")
    def test_api_generate_and_detail(self, _mock_thread):
        run = self._make_completed_run()

        r = self.client.post(f"/api/mitigation/run/{run.pk}/generate/")
        self.assertEqual(r.status_code, 201)
        body = r.json()["data"]
        self.assertEqual(body["status"], "pending")
        plan_id = body["id"]

        r = self.client.get(f"/api/mitigation/{plan_id}/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("status", r.json()["data"])

        # A second generate re-dispatches the same plan (200).
        r = self.client.post(f"/api/mitigation/run/{run.pk}/generate/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["data"]["id"], plan_id)

    @mock.patch("segments.mitigation.mitigation.planner.threading.Thread")
    def test_api_generate_requires_completed_run(self, _mock_thread):
        job = ScanJob.objects.using("default").create(
            source_type="source_code",
            target="pending/app",
            mode="actual",
            status="completed",
            findings_count=0,
        )
        queued = AnalysisRun.objects.using("default").create(
            scan_job=job,
            mode="actual",
            status=AnalysisRun.Status.QUEUED,
            input_payload={"repository": {"name": "x"}, "findings": []},
            raw_system_context={"network": {}},
        )
        r = self.client.post(f"/api/mitigation/run/{queued.pk}/generate/")
        self.assertEqual(r.status_code, 400)

    @mock.patch("segments.mitigation.mitigation.planner.threading.Thread")
    def test_api_list(self, _mock_thread):
        run = self._make_completed_run()
        with mock.patch("segments.mitigation.mitigation.planner.threading.Thread"):
            trigger_mitigation(run, "default")

        r = self.client.get("/api/mitigation/")
        self.assertEqual(r.status_code, 200)
        data = r.json()["data"]
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 1)
        self.assertIn("run_id", data[0])
        self.assertNotIn("document", data[0])