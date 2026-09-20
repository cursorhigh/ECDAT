"""Tests for the analysis runner pipeline and API endpoints."""

import json
import os
from unittest import mock

from django.test import Client, TestCase, override_settings

from segments.scraping.discovery.classifier import classify_asset
from segments.scraping.discovery.models import CryptoAsset, RawFinding, ScanJob
from segments.scraping.discovery.normalizer import normalize_finding

from .models import AnalysisRun
from .payload_builder import build_analysis_payload, default_raw_system_context
from .runner import _auto_continue, continue_pending, execute_analysis, pending_analysis, start_analysis

_FORCE_FALLBACK_PROVIDERS = {
    "GEMINI_API_KEY_CBOM": "",
    "GEMINI_API_KEY_RISK": "",
    "GEMINI_API_KEY_HNDL": "",
    "GEMINI_API_KEY_MOSCA": "",
    "GEMINI_API_KEY": "",
}


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class AnalysisRunnerTests(TestCase):
    """Runner + API tests using only deterministic fallback providers."""

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
        from segments.ml.hndl.llm_provider import get_hndl_provider

        self.assertEqual(type(get_hndl_provider()).__name__, "FallbackHNDLProvider")
        self.client = Client()

    def _make_job(self, target="work/app", status="completed"):
        return ScanJob.objects.using("default").create(
            source_type="source_code",
            target=target,
            mode="actual",
            status=status,
            config={"scan_type": "specified"},
        )

    def _seed_raw(self, job, raw_json, location=None):
        if location is None:
            location = raw_json.get("location", "")
        raw = RawFinding.objects.using("default").create(
            scan_job=job,
            mode="actual",
            source_type="source_code",
            location=location,
            raw_json=raw_json,
        )
        norm = normalize_finding(raw, using="default")
        classify_asset(norm, using="default")
        return raw, norm

    def _make_run(self, job, payload=None, status="queued"):
        return AnalysisRun.objects.using("default").create(
            scan_job=job,
            mode="actual",
            status=status,
            input_payload=payload if payload is not None else build_analysis_payload(job),
            raw_system_context=default_raw_system_context(job),
        )

    def test_execute_analysis_completes_with_artifacts(self):
        job = self._make_job()
        self._seed_raw(
            job,
            {"location": "a/RSA.java", "family": "rsa", "algorithm": "RSA", "confidence": 0.9},
        )
        self._seed_raw(
            job,
            {
                "location": "b/Hash.java",
                "family": "hash",
                "algorithm": "SHA256",
                "confidence": 0.8,
            },
        )
        run = self._make_run(job)

        with mock.patch("segments.ml.analysis.runner._auto_mitigation"):
            execute_analysis(run.pk, "actual")

        run.refresh_from_db()
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.progress, 100)
        self.assertEqual(run.cbom_document["format"], "ECDAT-CBOM")
        self.assertEqual(len(run.executive_summary["rows"]), 2)
        self.assertEqual(run.assessments.count(), 2)
        self.assertIn("data_context", run.risk_context)
        for a in run.assessments.all():
            self.assertTrue(a.hndl_result.get("hndl"))
            self.assertTrue(a.mosca_result.get("mosca_assessment"))

    def test_write_back_fills_key_size_and_curve(self):
        job = self._make_job()
        self._seed_raw(
            job,
            {
                "location": "a/RSA.java",
                "family": "rsa",
                "algorithm": "RSA",
                "confidence": 0.9,
                "raw": {"strings": ["rsa.generate_private_key(key_size=2048)"]},
            },
        )
        self._seed_raw(
            job,
            {
                "location": "b/ECDSA.java",
                "family": "ecc",
                "algorithm": "ECDSA",
                "confidence": 0.9,
                "curve": "P-256",
            },
        )

        rsa_asset = CryptoAsset.objects.using("default").get(algorithm="RSA")
        ecdsa_asset = CryptoAsset.objects.using("default").get(algorithm="ECDSA")
        self.assertIsNone(rsa_asset.key_size)

        run = self._make_run(job)
        with mock.patch("segments.ml.analysis.runner._auto_mitigation"):
            execute_analysis(run.pk, "actual")

        rsa_asset.refresh_from_db()
        ecdsa_asset.refresh_from_db()
        self.assertEqual(rsa_asset.key_size, 2048)
        self.assertEqual(ecdsa_asset.curve, "P-256")

    @mock.patch("segments.ml.analysis.runner.threading.Thread")
    def test_start_analysis_creates_queued_run(self, mock_thread):
        job = self._make_job()

        run = start_analysis(job)

        self.assertEqual(run.status, "queued")
        self.assertEqual(run.progress, 0)
        self.assertIsNotNone(run.pk)
        self.assertEqual(run.scan_job_id, job.pk)

    @mock.patch("segments.ml.analysis.runner.threading.Thread")
    def test_api_start_and_detail(self, mock_thread):
        job = self._make_job()

        r = self.client.post(
            "/api/analysis/start/",
            data=json.dumps({"scan_job": job.pk}),
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 201)
        body = r.json()["data"]
        self.assertEqual(body["status"], "queued")
        run_id = body["id"]

        r = self.client.get(f"/api/analysis/{run_id}/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("status", r.json()["data"])

        r = self.client.post(
            "/api/analysis/start/",
            data=json.dumps({"scan_job": 999999}),
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 400)

        failed_job = self._make_job(target="broken/app", status="failed")
        r = self.client.post(
            "/api/analysis/start/",
            data=json.dumps({"scan_job": failed_job.pk}),
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 400)

    @mock.patch("segments.ml.analysis.runner.threading.Thread")
    def test_api_list(self, mock_thread):
        job = self._make_job()
        start_analysis(job)

        r = self.client.get("/api/analysis/")

        self.assertEqual(r.status_code, 200)
        data = r.json()["data"]
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 1)
        self.assertIn("scan_job_id", data[0])

    def test_execute_analysis_failure_sets_failed_status(self):
        job = self._make_job()
        self._seed_raw(
            job,
            {"location": "a/RSA.java", "family": "rsa", "algorithm": "RSA", "confidence": 0.9},
        )
        run = self._make_run(job)

        with mock.patch("segments.ml.analysis.runner.CBOMAgent") as mocked:
            mocked.side_effect = ValueError("cbom exploded")
            execute_analysis(run.pk, "actual")

        run.refresh_from_db()
        self.assertEqual(run.status, "failed")
        self.assertTrue(run.error)
        self.assertEqual(run.progress, 0)


class PendingContextTests(TestCase):
    """Auto-staged analysis waits for a context choice (default after timeout)."""

    @override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
    def test_pending_analysis_creates_awaiting_run(self):
        job = ScanJob.objects.using("default").create(
            source_type="source_code",
            target="pending/app",
            mode="actual",
            status="completed",
            findings_count=1,
        )
        with mock.patch("segments.ml.analysis.runner.threading.Thread"):
            run = pending_analysis(job)

        self.assertEqual(run.status, "awaiting_context")
        self.assertIsNotNone(run.await_until)
        self.assertEqual(run.scan_job_id, job.pk)
        self.assertEqual(run.raw_system_context, default_raw_system_context(job))
        self.assertEqual(
            AnalysisRun.objects.using("default").filter(scan_job=job).count(), 1
        )

    @override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
    @mock.patch("segments.ml.analysis.runner._dispatch")
    def test_auto_continue_queues_with_default_after_timeout(self, mock_dispatch):
        job = ScanJob.objects.using("default").create(
            source_type="source_code",
            target="pending/app",
            mode="actual",
            status="completed",
            findings_count=1,
        )
        with mock.patch("segments.ml.analysis.runner.threading.Thread"):
            run = pending_analysis(job)

        _auto_continue(run.pk, run.mode, "default", 0)

        run.refresh_from_db()
        self.assertEqual(run.status, "queued")
        self.assertIsNone(run.await_until)
        mock_dispatch.assert_called_once()
        self.assertEqual(mock_dispatch.call_args.args[0].pk, run.pk)

    @override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
    @mock.patch("segments.ml.analysis.runner._dispatch")
    def test_continue_pending_uses_custom_context(self, mock_dispatch):
        job = ScanJob.objects.using("default").create(
            source_type="source_code",
            target="pending/app",
            mode="actual",
            status="completed",
            findings_count=1,
        )
        with mock.patch("segments.ml.analysis.runner.threading.Thread"):
            run = pending_analysis(job)

        custom = default_raw_system_context(job)
        custom["network"]["publicly_accessible"] = True
        continue_pending(run, custom, db="default")

        run.refresh_from_db()
        self.assertEqual(run.status, "queued")
        self.assertEqual(run.raw_system_context["network"]["publicly_accessible"], True)
        mock_dispatch.assert_called_once()

    @override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
    def test_awaiting_endpoint_lists_pending_run(self):
        from django.test import Client

        job = ScanJob.objects.using("default").create(
            source_type="source_code",
            target="pending/app",
            mode="actual",
            status="completed",
            findings_count=1,
        )
        with mock.patch("segments.ml.analysis.runner.threading.Thread"):
            pending_analysis(job)

        r = Client().get("/api/analysis/awaiting/")
        self.assertEqual(r.status_code, 200)
        rows = r.json()["data"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["scan_job_id"], job.pk)
        self.assertGreater(rows[0]["seconds_left"], 0)

    @override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
    @mock.patch("segments.ml.analysis.runner.threading.Thread")
    def test_api_start_redemption_reuses_awaiting_run(self, _mock_thread):
        from django.test import Client

        job = ScanJob.objects.using("default").create(
            source_type="source_code",
            target="pending/app",
            mode="actual",
            status="completed",
            findings_count=1,
        )
        run = pending_analysis(job)

        custom = default_raw_system_context(job)
        custom["data"]["types"] = ["test_data"]
        r = Client().post(
            "/api/analysis/start/",
            data=json.dumps({"scan_job": job.pk, "raw_system_context": custom}),
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()["data"]
        self.assertEqual(body["id"], run.pk)
        self.assertEqual(body["status"], "queued")

        run.refresh_from_db()
        self.assertEqual(run.status, "queued")
        self.assertEqual(run.raw_system_context["data"]["types"], ["test_data"])
        self.assertEqual(
            AnalysisRun.objects.using("default").filter(scan_job=job).count(), 1
        )