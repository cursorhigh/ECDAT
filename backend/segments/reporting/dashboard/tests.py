"""Tests for the reporting (estate-metrics) API.

ECDAT is a backend-only API service, so these cover the JSON endpoints that
replaced the server-rendered dashboard pages.
"""
from django.test import TestCase

from core.models import log_action
from segments.ml.analysis.models import AnalysisRun
from segments.scraping.discovery.models import CryptoAsset, NormalizedFinding, RawFinding, ScanJob
from segments.mitigation.mitigation.models import MitigationPlan
from segments.reporting.dashboard.views import _pqc_workflow

ZERO_RISK = {
    "vulnerable": 0,
    "weak": 0,
    "moderate": 0,
    "pqc": 0,
    "unknown": 0,
}


class WorkflowBuilderTests(TestCase):
    def test_workflow_has_ordered_connected_steps(self):
        steps = _pqc_workflow(0, ZERO_RISK, [], mitigation_done=False)
        self.assertEqual(len(steps), 5)
        self.assertEqual(
            [s["key"] for s in steps],
            ["discover", "assess", "prioritize", "mitigate", "report"],
        )
        for s in steps:
            self.assertTrue(s.get("api").startswith("/api/"))
            self.assertEqual(s.get("done"), False)

    def test_workflow_done_flags_propagate(self):
        steps = _pqc_workflow(6, ZERO_RISK, [{"asset_date_critical": True}], analysis_done=True, mitigation_done=True)
        by_key = {s["key"]: s for s in steps}
        self.assertTrue(by_key["discover"]["done"])
        self.assertTrue(by_key["assess"]["done"])
        self.assertTrue(by_key["prioritize"]["done"])
        self.assertTrue(by_key["mitigate"]["done"])
        self.assertTrue(by_key["report"]["done"])
        self.assertIn("mitigation", by_key["mitigate"]["name"].lower())

    def test_workflow_api_hints_point_at_real_endpoints(self):
        steps = _pqc_workflow(0, ZERO_RISK, [], mitigation_done=False)
        for s in steps:
            self.assertTrue(s["api"].startswith("/api/"))
        self.assertEqual(steps[0]["api"], "/api/scans/")
        self.assertEqual(steps[-1]["api"], "/api/reports/full.json")


class OverviewEndpointTests(TestCase):
    def setUp(self):
        self.scan = ScanJob.objects.create(
            target="payments-core",
            source_type=ScanJob.SourceType.SOURCE_CODE,
            status=ScanJob.Status.COMPLETED,
        )
        raw = RawFinding.objects.create(
            scan_job=self.scan,
            location="src/crypto/rsa_key.py",
        )
        NormalizedFinding.objects.create(
            raw_finding=raw,
            family=NormalizedFinding.AlgorithmFamily.RSA,
            algorithm="RSA",
            key_size=2048,
        )
        CryptoAsset.objects.create(
            name="payments-signing-key",
            family=NormalizedFinding.AlgorithmFamily.RSA,
            algorithm="RSA",
            key_size=2048,
            source_type=ScanJob.SourceType.SOURCE_CODE,
        )
        self.run = AnalysisRun.objects.create(
            scan_job=self.scan,
            status=AnalysisRun.Status.COMPLETED,
            executive_summary={
                "rows": [
                    {
                        "asset_id": "f1",
                        "algorithm": "RSA-2048",
                        "algorithm_category": "classical",
                        "overall_risk": "HIGH",
                        "migration_priority": "URGENT",
                        "quantum_vulnerable": True,
                    }
                ],
            },
        )

    def test_overview_before_mitigation(self):
        resp = self.client.get("/api/reporting/overview/")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()["data"]
        self.assertIn("kpis", body)
        self.assertIn("risk_split", body)
        self.assertIn("vuln_priorities", body)
        self.assertIn("workflow", body)
        self.assertEqual(body["mitigation_done"], False)
        self.assertEqual(body["kpis"]["plan_count"], 0)
        self.assertEqual(body["analysis_done"], True)
        self.assertEqual(body["kpis"]["assets"], 1)
        self.assertEqual(body["risk_split"][0]["count"], 1)

    def test_overview_after_mitigation(self):
        MitigationPlan.objects.create(
            run=self.run,
            status=MitigationPlan.Status.COMPLETE,
            document={"summary": {"assets": 1}},
        )
        resp = self.client.get("/api/reporting/overview/")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()["data"]
        self.assertEqual(body["mitigation_done"], True)
        self.assertEqual(body["kpis"]["plan_count"], 1)
        self.assertGreater(body["kpis"]["mitigation_assets"], 0)
        workflow = {s["key"]: s["done"] for s in body["workflow"]}
        self.assertTrue(all(workflow.values()))


class ReportingEndpointTests(TestCase):
    def setUp(self):
        self.scan = ScanJob.objects.create(
            target="api-gateway",
            source_type=ScanJob.SourceType.SOURCE_CODE,
            status=ScanJob.Status.COMPLETED,
        )
        raw = RawFinding.objects.create(
            scan_job=self.scan,
            location="gw/keys/jwt_rsa.py",
        )
        self.finding = NormalizedFinding.objects.create(
            raw_finding=raw,
            family=NormalizedFinding.AlgorithmFamily.RSA,
            algorithm="RSA",
            key_size=2048,
        )
        self.asset = CryptoAsset.objects.create(
            name="api-gateway-signer",
            family=NormalizedFinding.AlgorithmFamily.RSA,
            algorithm="RSA",
            key_size=2048,
            source_type=ScanJob.SourceType.SOURCE_CODE,
        )

    def test_pipeline_endpoint(self):
        resp = self.client.get("/api/reporting/pipeline/")
        self.assertEqual(resp.status_code, 200)
        stages = resp.json()["data"]["stages"]
        self.assertEqual(
            [s["key"] for s in stages],
            ["scan", "raw", "norm", "asset", "graph"],
        )
        by_key = {s["key"]: s for s in stages}
        self.assertEqual(by_key["scan"]["count"], 1)
        self.assertEqual(by_key["asset"]["count"], 1)
        self.assertTrue(by_key["asset"]["done"])

    def test_audit_endpoint_lists_entries(self):
        log_action("scan_created", "Test scan created", "scanjob", self.scan.pk)
        resp = self.client.get("/api/reporting/audit/")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()["data"]
        self.assertIn("entries", body)
        self.assertGreaterEqual(body["count"], 1)
        self.assertEqual(body["entries"][0]["action"], "scan_created")
        self.assertIn("created_at", body["entries"][0])

    def test_health_endpoint(self):
        resp = self.client.get("/api/health/")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()["data"]
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["service"], "ecdat-backend")