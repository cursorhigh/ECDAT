"""Tests for work-session scoping helpers and session endpoints."""

import json

from django.test import Client, TestCase, override_settings

from segments.scraping.discovery.models import ScanJob

from .api import create_api_key
from .models import ApiKey, WorkSession
from .sessions import clear_thread_session, create_scan_session, scope, thread_session_id


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class WorkSessionTests(TestCase):
    """Session endpoints, the scope() helper and reset isolation."""

    def setUp(self):
        self.client = Client()

    def _job(self, target, session=None):
        return ScanJob.objects.using("default").create(
            source_type="source_code",
            target=target,
            mode="actual",
            status="queued",
            session_id=session.pk if session else None,
        )

    def test_create_session_then_info_reports_it(self):
        r = self.client.post(
            "/api/session/create/",
            data=json.dumps({"name": "S1"}),
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 200)
        session_id = r.json()["data"]["id"]
        self.assertTrue(session_id)

        r = self.client.get("/api/session/info/")
        self.assertEqual(r.status_code, 200)
        body = r.json()["data"]
        self.assertEqual(body["session_id"], session_id)
        self.assertEqual(body["session_name"], "S1")

    def test_scope_helper_narrows_to_session(self):
        s1 = WorkSession.objects.create(name="Scope-A")
        s2 = WorkSession.objects.create(name="Scope-B")
        job_a = self._job("a", session=s1)
        self._job("b", session=s2)
        self._job("g")  # legacy/global row

        self.assertEqual(scope(ScanJob.objects, s1.pk).count(), 1)
        self.assertEqual(scope(ScanJob.objects, s1.pk).first().pk, job_a.pk)
        self.assertEqual(scope(ScanJob.objects, s2.pk).count(), 1)
        self.assertEqual(scope(ScanJob.objects, None).count(), 3)

    def test_session_info_counts_isolate_sessions(self):
        s1 = WorkSession.objects.create(name="Info-A")
        s2 = WorkSession.objects.create(name="Info-B")
        job_a = self._job("a", session=s1)
        self._job("b", session=s2)
        self._job("g")  # legacy/global row

        self.client.post(f"/api/session/switch/{s1.pk}/")
        r = self.client.get("/api/session/info/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["data"]["counts"]["scans"], 1)

        self.client.post(f"/api/session/switch/{s2.pk}/")
        r = self.client.get("/api/session/info/")
        self.assertEqual(r.json()["data"]["counts"]["scans"], 1)
        self.assertEqual(r.json()["data"]["counts"]["raw_findings"], 0)

        # "All data" (no session) shows every row, including legacy NULL ones.
        self.client.post("/api/session/switch/0/")
        r = self.client.get("/api/session/info/")
        self.assertEqual(r.json()["data"]["counts"]["scans"], 3)

    def test_reset_deletes_only_current_sessions_scanjobs(self):
        s1 = WorkSession.objects.create(name="Reset-A")
        s2 = WorkSession.objects.create(name="Reset-B")
        job_a = self._job("a", session=s1)
        job_b = self._job("b", session=s2)

        self.client.post(f"/api/session/switch/{s1.pk}/")
        r = self.client.post("/api/session/reset/")
        self.assertEqual(r.status_code, 200)
        self.assertGreaterEqual(r.json()["data"]["deleted"]["scan_jobs"], 1)

        self.assertFalse(ScanJob.objects.filter(pk=job_a.pk).exists())
        self.assertTrue(ScanJob.objects.filter(pk=job_b.pk).exists())
        # The workspace itself is deleted too and the active session clears.
        self.assertFalse(WorkSession.objects.filter(pk=s1.pk).exists())
        self.assertTrue(WorkSession.objects.filter(pk=s2.pk).exists())
        info = self.client.get("/api/session/info/").json()["data"]
        self.assertEqual(info["session_id"], 0)
        self.assertEqual(info["scope"], "all")

    def test_create_scan_session_returns_unique_session(self):
        R = type("R", (), {"session": {}})
        clear_thread_session()

        ws1 = create_scan_session(R(), "x")
        ws2 = create_scan_session(R(), "x")

        self.assertNotEqual(ws1.pk, ws2.pk)
        self.assertNotEqual(ws1.name, ws2.name)
        self.assertTrue(ws1.name.startswith("x · "))
        # The request's session was switched to the new pk.
        r = R()
        ws = create_scan_session(r, "y")
        self.assertEqual(r.session["ecdat_session_id"], ws.pk)
        self.assertEqual(thread_session_id(), ws.pk)


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual", "REQUIRE_API_KEY": True})
class ApiKeyAuthTests(TestCase):
    """API-key enforcement on /api/ routes."""

    def setUp(self):
        self.client = Client()
        self.key, self.full_key = create_api_key("test-suite", db="default")

    def test_missing_key_is_rejected_with_envelope(self):
        r = self.client.get("/api/scans/")
        self.assertEqual(r.status_code, 401)
        body = r.json()
        self.assertFalse(body["success"])
        self.assertEqual(body["code"], "unauthorized")
        self.assertEqual(r["WWW-Authenticate"], 'Api-Key realm="ecdat"')

    def test_valid_key_is_accepted(self):
        r = self.client.get("/api/scans/", HTTP_X_API_KEY=self.full_key)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["success"])

    def test_authorization_bearer_scheme_accepted(self):
        r = self.client.get("/api/scans/", HTTP_AUTHORIZATION=f"Bearer {self.full_key}")
        self.assertEqual(r.status_code, 200)

    def test_invalid_key_is_rejected(self):
        r = self.client.get("/api/scans/", HTTP_X_API_KEY="ecdat_deadbeef_wrong")
        self.assertEqual(r.status_code, 401)

    def test_revoked_key_is_rejected(self):
        ApiKey.objects.using("default").filter(pk=self.key.pk).update(is_active=False)
        r = self.client.get("/api/scans/", HTTP_X_API_KEY=self.full_key)
        self.assertEqual(r.status_code, 401)

    def test_health_is_exempt(self):
        r = self.client.get("/api/health/")
        self.assertEqual(r.status_code, 200)

    def test_valid_key_updates_last_used(self):
        self.assertIsNone(ApiKey.objects.using("default").get(pk=self.key.pk).last_used_at)
        self.client.get("/api/scans/", HTTP_X_API_KEY=self.full_key)
        self.assertIsNotNone(ApiKey.objects.using("default").get(pk=self.key.pk).last_used_at)

    def test_auth_disabled_allows_anonymous(self):
        with override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual", "REQUIRE_API_KEY": False}):
            r = self.client.get("/api/scans/")
        self.assertEqual(r.status_code, 200)