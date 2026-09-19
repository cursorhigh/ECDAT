"""Tests for the dashboard views: pipeline workflow ordering, plan state and
page rendering."""

from django.test import TestCase
from django.urls import reverse

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
            self.assertTrue(s.get("href"))
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
        self.assertEqual(by_key["report"]["href"], reverse("dashboard-reports"))

    def test_workflow_hrefs_match_url_names(self):
        steps = _pqc_workflow(0, ZERO_RISK, [], mitigation_done=False)
        for s in steps:
            self.assertTrue(s["href"].startswith("/"))
        self.assertEqual(steps[0]["href"], reverse("dashboard-discovery"))
        self.assertEqual(steps[-1]["href"], reverse("dashboard-reports"))


class OverviewWorkflowStateTests(TestCase):
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

    def test_overview_renders_before_mitigation(self):
        resp = self.client.get(reverse("dashboard-overview"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "PQC Readiness Pipeline")
        self.assertContains(resp, "0", html=False)
        self.assertEqual(resp.context["mitigation_done"], False)
        self.assertEqual(resp.context["plan_count"], 0)
        self.assertTrue(resp.context["analysis_done"])

    def test_overview_renders_after_mitigation(self):
        MitigationPlan.objects.create(
            run=self.run,
            status=MitigationPlan.Status.COMPLETE,
            document={"summary": {"assets": 1}},
        )
        resp = self.client.get(reverse("dashboard-overview"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context["mitigation_done"], True)
        self.assertEqual(resp.context["plan_count"], 1)
        self.assertGreater(resp.context["mitigation_assets"], 0)
        workflow = {s["key"]: s["done"] for s in resp.context["workflow"]}
        self.assertTrue(all(workflow.values()))


class DashboardPageRenderTests(TestCase):
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
                "stats": {"assets": 1, "urgent": 1, "critical": 0, "hndl_applicable": 1},
            },
        )
        MitigationPlan.objects.create(
            run=self.run,
            status=MitigationPlan.Status.COMPLETE,
            document={"summary": {"assets": 1}},
        )

    def test_pages_render_200(self):
        for name, marker in [
            ("dashboard-overview", "PQC Readiness Pipeline"),
            ("dashboard-discovery", "Discovery Pipeline"),
            ("dashboard-inventory", "Discovery — All Categories"),
            ("dashboard-graph", "Correlation Graph"),
            ("dashboard-analysis", "Run analysis"),
            ("dashboard-mitigation", "Generate a plan"),
            ("dashboard-reports", "Full-pipeline report"),
            ("dashboard-audit", "Activity History"),
        ]:
            resp = self.client.get(reverse(name))
            self.assertEqual(resp.status_code, 200, name)
            if marker:
                self.assertContains(resp, marker)

    def test_analysis_detail_renders_200(self):
        resp = self.client.get(reverse("dashboard-analysis-detail", args=[self.run.pk]))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Executive Summary")

    def test_mitigation_detail_renders_200(self):
        plan = MitigationPlan.objects.get(run=self.run)
        resp = self.client.get(reverse("dashboard-mitigation-detail", args=[plan.pk]))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Mitigation Plan #{0}".format(plan.pk))