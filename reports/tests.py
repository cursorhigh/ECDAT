"""Tests for the full-pipeline report builder and its API endpoints."""

import base64
import json
from unittest import mock

from django.test import TestCase
from django.urls import reverse

from analysis.models import AnalysisRun
from discovery.models import CryptoAsset, NormalizedFinding, RawFinding, ScanJob
from mitigation.models import MitigationPlan
from reports.report_builder import build_report
from reports.pdf_renderer import _find_browser, render_pdf


class ReportBuilderTests(TestCase):
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
        norm = NormalizedFinding.objects.create(
            raw_finding=raw,
            family=NormalizedFinding.AlgorithmFamily.RSA,
            algorithm="RSA",
            key_size=2048,
        )
        self.asset = CryptoAsset.objects.create(
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
                "stats": {"assets": 1, "urgent": 1, "critical": 0, "hndl_applicable": 1},
            },
        )

    def test_build_report_sections_present(self):
        report = build_report()
        html = report["html"]
        self.assertIn("Full Pipeline Report", html)
        self.assertIn("Executive Summary", html)
        self.assertIn("Discovery Pipeline", html)
        self.assertIn("Inventory &amp; Quantum Risk", html)
        self.assertIn("Analysis &amp; Assessment", html)
        self.assertIn("Appendix", html)
        self.assertIn("payments-signing-key", html)
        self.assertIn("Vulnerable", html)
        self.assertTrue(report["filename"].endswith(".pdf"))

    def test_build_report_scopes_latest_completed_run(self):
        from core.modes import ACTUAL_DB

        MitigationPlan.objects.create(run=self.run, status=MitigationPlan.Status.COMPLETE)
        report = build_report(sid=None, db=ACTUAL_DB)
        self.assertIn("payments-signing-key", report["html"])
        self.assertEqual(
            report["data"]["meta"]["scope_label"], "All data (no workspace filter)"
        )
        self.assertIsNotNone(report["data"]["mitigation"])
        self.assertEqual(report["data"]["mitigation"]["run_id"], self.run.pk)
        self.assertIn("Executive Summary", report["html"])

    def test_renderer_finds_browser_or_raises(self):
        browser = _find_browser()
        if browser is None:
            with self.assertRaises(RuntimeError):
                render_pdf("<html><body>hi</body></html>")
        else:
            pdf = render_pdf("<html><body><h1>Hello</h1></body></html>")
            self.assertTrue(pdf.startswith(b"%PDF"))
            self.assertGreater(len(pdf), 200)


class ReportApiTests(TestCase):
    def setUp(self):
        ScanJob.objects.create(
            target="api-gateway",
            source_type=ScanJob.SourceType.SOURCE_CODE,
            status=ScanJob.Status.COMPLETED,
        )

    def test_full_report_json_returns_b64_pdf(self):
        fake_pdf = b"%PDF-1.4\nfake binary pdf payload for tests"
        with mock.patch("reports.views.render_pdf", return_value=fake_pdf) as mocked:
            resp = self.client.post(reverse("report-full-json"))
        self.assertEqual(resp.status_code, 200)
        payload = json.loads(resp.content)
        self.assertEqual(payload["format"], "pdf")
        self.assertTrue(payload["filename"].endswith(".pdf"))
        self.assertEqual(payload["mime"], "application/pdf")
        self.assertEqual(payload["size"], len(fake_pdf))
        self.assertEqual(base64.b64decode(payload["b64"]), fake_pdf)
        mocked.assert_called_once()

    def test_full_report_json_html_fallback_when_no_pdf_engine(self):
        with mock.patch(
            "reports.views.render_pdf",
            side_effect=RuntimeError("no browser"),
        ):
            resp = self.client.post(reverse("report-full-json"))
        self.assertEqual(resp.status_code, 200)
        payload = json.loads(resp.content)
        self.assertEqual(payload["format"], "html")
        self.assertTrue(payload["filename"].endswith(".html"))
        self.assertIn("text/html", payload["mime"])
        self.assertIn("render_error", payload)
        html = base64.b64decode(payload["b64"]).decode("utf-8")
        self.assertIn("Full Pipeline Report", html)

    def test_full_report_html_endpoint(self):
        resp = self.client.get(reverse("report-full-html"))
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Full Pipeline Report", resp.content)

    def test_full_report_html_allows_sameorigin_framing(self):
        """The preview iframe on the Reports page must not be X-Frame-Options DENY."""
        resp = self.client.get(reverse("report-full-html"))
        self.assertEqual(resp["X-Frame-Options"], "SAMEORIGIN")