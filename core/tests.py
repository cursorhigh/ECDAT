"""Tests for work-session scoping helpers and session endpoints."""

import json

from django.test import Client, TestCase, override_settings

from segments.scraping.discovery.models import ScanJob

from .models import WorkSession
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
        session_id = r.json()["id"]
        self.assertTrue(session_id)

        r = self.client.get("/api/session/info/")
        self.assertEqual(r.status_code, 200)
        body = r.json()
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
        self.assertEqual(r.json()["counts"]["scans"], 1)

        self.client.post(f"/api/session/switch/{s2.pk}/")
        r = self.client.get("/api/session/info/")
        self.assertEqual(r.json()["counts"]["scans"], 1)
        self.assertEqual(r.json()["counts"]["raw_findings"], 0)

        # "All data" (no session) shows every row, including legacy NULL ones.
        self.client.post("/api/session/switch/0/")
        r = self.client.get("/api/session/info/")
        self.assertEqual(r.json()["counts"]["scans"], 3)

    def test_reset_deletes_only_current_sessions_scanjobs(self):
        s1 = WorkSession.objects.create(name="Reset-A")
        s2 = WorkSession.objects.create(name="Reset-B")
        job_a = self._job("a", session=s1)
        job_b = self._job("b", session=s2)

        self.client.post(f"/api/session/switch/{s1.pk}/")
        r = self.client.post("/api/session/reset/")
        self.assertEqual(r.status_code, 200)
        self.assertGreaterEqual(r.json()["deleted"]["scan_jobs"], 1)

        self.assertFalse(ScanJob.objects.filter(pk=job_a.pk).exists())
        self.assertTrue(ScanJob.objects.filter(pk=job_b.pk).exists())
        # The workspace itself is deleted too and the active session clears.
        self.assertFalse(WorkSession.objects.filter(pk=s1.pk).exists())
        self.assertTrue(WorkSession.objects.filter(pk=s2.pk).exists())
        info = self.client.get("/api/session/info/").json()
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