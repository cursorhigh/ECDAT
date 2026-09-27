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

    def test_scope_helper_returns_nothing_without_a_session(self):
        """No active session means no data, not every session's data.

        Returning the unfiltered queryset here is what let two unrelated scans
        render as one list, so the absence of a session has to read as empty.
        """
        s1 = WorkSession.objects.create(name="Scope-A")
        self._job("a", session=s1)
        self._job("g")  # legacy/global row

        self.assertEqual(scope(ScanJob.objects, None).count(), 0)
        self.assertEqual(scope(ScanJob.objects, 0).count(), 0)
        self.assertFalse(scope(ScanJob.objects, None).exists())

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

        # No session selected means no scope, so nothing is counted. This used to
        # report every row in the estate, which put another scan's totals in the
        # scope banner for the scan actually on screen.
        self.client.post("/api/session/switch/0/")
        r = self.client.get("/api/session/info/")
        self.assertEqual(r.json()["data"]["counts"]["scans"], 0)
        self.assertEqual(r.json()["data"]["counts"]["raw_findings"], 0)
        self.assertEqual(r.json()["data"]["scope"], "none")

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
        self.assertEqual(info["scope"], "none")

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

@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class ScanHistoryTests(TestCase):
    """Audit is the one place that spans sessions, so it has to be trustworthy.

    Removing the "all data" scope left no way to reach a previous scan, so the
    scan history has to be complete and clearly attributed. A session *is* a scan,
    which is what makes "one scan, one session" readable here.
    """

    def setUp(self):
        from core.models import WorkSession

        from segments.scraping.discovery.models import ScanJob

        self.client = Client()
        self.first = WorkSession.objects.create(name="scan-one")
        self.second = WorkSession.objects.create(name="scan-two")
        self.job_a = ScanJob.objects.create(
            session=self.first, source_type="source_code", target="/one", status="completed",
        )
        self.job_b = ScanJob.objects.create(
            session=self.second, source_type="binary", target="/two", status="partial",
        )

    def test_history_spans_sessions(self):
        """Both scans are listed even though no session is selected."""
        r = self.client.get("/api/session/scan-history/")
        self.assertEqual(r.status_code, 200)
        data = r.json()["data"]
        ids = {s["id"] for s in data["sessions"]}
        self.assertIn(self.first.pk, ids)
        self.assertIn(self.second.pk, ids)

    def test_each_session_carries_its_own_scans(self):
        """A session's scans are its own, never a neighbour's."""
        data = self.client.get("/api/session/scan-history/").json()["data"]
        by_id = {s["id"]: s for s in data["sessions"]}
        self.assertEqual([j["id"] for j in by_id[self.first.pk]["scans"]], [self.job_a.pk])
        self.assertEqual([j["id"] for j in by_id[self.second.pk]["scans"]], [self.job_b.pk])

    def test_scan_records_carry_status_and_counts(self):
        data = self.client.get("/api/session/scan-history/").json()["data"]
        jobs = {j["id"]: j for s in data["sessions"] for j in s["scans"]}
        self.assertEqual(jobs[self.job_b.pk]["status"], "partial")
        self.assertEqual(jobs[self.job_b.pk]["source_type"], "binary")
        self.assertIn("findings_count", jobs[self.job_b.pk])

    def test_active_session_is_marked(self):
        self.client.post(f"/api/session/switch/{self.second.pk}/")
        data = self.client.get("/api/session/scan-history/").json()["data"]
        self.assertEqual(data["active_session_id"], self.second.pk)
        marked = {s["id"]: s["is_active"] for s in data["sessions"]}
        self.assertTrue(marked[self.second.pk])
        self.assertFalse(marked[self.first.pk])

    def test_history_is_newest_first(self):
        data = self.client.get("/api/session/scan-history/").json()["data"]
        created = [s["created_at"] for s in data["sessions"]]
        self.assertEqual(created, sorted(created, reverse=True))

    def test_history_works_with_no_session_selected(self):
        """The point of audit: it must not depend on a scope being active."""
        self.client.post("/api/session/switch/0/")
        r = self.client.get("/api/session/scan-history/")
        self.assertEqual(r.status_code, 200)
        self.assertGreaterEqual(r.json()["data"]["count"], 2)

    def test_bad_limit_is_ignored(self):
        r = self.client.get("/api/session/scan-history/?limit=abc")
        self.assertEqual(r.status_code, 200)

    def test_history_requires_get(self):
        self.assertEqual(self.client.post("/api/session/scan-history/").status_code, 405)

@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class NoSessionLeakTests(TestCase):
    """With no scan selected, every tab must show nothing.

    Several read paths filtered by hand with "if a session is set, filter by it",
    which left the whole estate visible whenever none was selected. The graph
    tab was the reported symptom; these cover every tab so the pattern cannot
    come back one endpoint at a time.
    """

    def setUp(self):
        from core.models import WorkSession
        from segments.scraping.discovery.models import (
            AssetRelation,
            CryptoAsset,
            NormalizedFinding,
            RawFinding,
            ScanJob,
        )

        self.client = Client()
        # Two sessions, so a leak has something to leak.
        first = WorkSession.objects.create(name="leak-one")
        second = WorkSession.objects.create(name="leak-two")
        for index, session in enumerate((first, second)):
            job = ScanJob.objects.create(
                session=session, source_type="source_code",
                target=f"/scan-{index}", status="completed",
            )
            raw = RawFinding.objects.create(
                session=session, scan_job=job, location=f"src/{index}.js",
            )
            NormalizedFinding.objects.create(
                session=session, raw_finding=raw,
                family=NormalizedFinding.AlgorithmFamily.RSA,
                algorithm="RSA", key_size=2048,
            )
            CryptoAsset.objects.create(
                session=session, name=f"key-{index}",
                family=NormalizedFinding.AlgorithmFamily.RSA,
                algorithm="RSA", key_size=2048, source_type="source_code",
            )
        AssetRelation.objects.create(
            session=first, from_asset_id=1, to_asset_id=1, relation_type="context",
        )
        # No session is ever switched to.

    def test_findings_assets_dependencies_and_scans_are_empty(self):
        for url in ("/api/scans/", "/api/normalized-findings/", "/api/assets/",
                    "/api/dependencies/"):
            with self.subTest(url=url):
                body = self.client.get(url).json()["data"]
                self.assertEqual(body["count"], 0, msg=url)

    def test_graph_index_shows_no_nodes_or_edges(self):
        body = self.client.get("/api/graph-index/").json()["data"]
        self.assertEqual(body["stats"]["nodes"], 0)
        self.assertEqual(body["stats"]["edges"], 0)
        self.assertEqual(body["nodes"], [])
        self.assertEqual(body["edges"], [])

    def test_graph_data_shows_no_assets_or_relations(self):
        body = self.client.get("/api/graph/").json()["data"]
        self.assertEqual(body["assets"], [])
        self.assertEqual(body["asset_relations"], [])
        self.assertEqual(body["dependency_nodes"], [])

    def test_handoff_is_empty_and_does_not_claim_the_contract_holds(self):
        """No dataset means nothing verified, which is not the same as verified."""
        body = self.client.get("/api/handoff/?summary=1").json()["data"]
        self.assertEqual(body["counts"]["findings"], 0)
        self.assertEqual(body["counts"]["assets"], 0)
        self.assertFalse(body["contract"]["satisfied"])
        self.assertNotIn("findings", body)

    def test_session_info_counts_only_the_active_session(self):
        body = self.client.get("/api/session/info/").json()["data"]
        self.assertEqual(body["counts"]["assets"], 0)
        self.assertEqual(body["counts"]["scans"], 0)
        self.assertEqual(body["scope"], "none")

    def test_selecting_a_session_shows_only_that_session(self):
        body = self.client.get("/api/session/info/").json()["data"]
        self.client.post(f"/api/session/switch/{body.get('session_id') or 1}/")
        scoped = self.client.get("/api/normalized-findings/").json()["data"]
        self.assertEqual(scoped["count"], 1, "a selected session sees its own finding only")


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class ViewExceptionEnvelopeTests(TestCase):
    """A view that raises must produce its own error, not a bare 500.

    Django's `convert_exception_to_response` turns a view exception into a plain
    500 before middleware's `except` can see it, so the envelope's error branch
    was unreachable: `ApiError` had never been raised anywhere and a view asking
    for a precise 409 still got a message-less 500. These lock in that a raised
    ApiError reaches the client with its status, code and message.
    """

    def setUp(self):
        from django.test import override_settings as _override
        from django.urls import path, clear_url_caches

        from core.api import ApiError

        import config.urls as urlconf

        self._original = list(urlconf.urlpatterns)
        client = Client()

        def precise(request):
            raise ApiError(409, "precise_code", "A precise, actionable message.")

        urlconf.urlpatterns = [path("api/precise-probe/", precise)] + self._original
        clear_url_caches()
        self.addCleanup(self._restore, urlconf, clear_url_caches)
        self.response = client.get("/api/precise-probe/")

    @staticmethod
    def _restore(urlconf, clear_url_caches):
        urlconf.urlpatterns = list(urlconf.urlpatterns)[1:]
        clear_url_caches()

    def test_raised_api_error_keeps_its_status_code_and_message(self):
        self.assertEqual(self.response.status_code, 409)
        body = self.response.json()
        self.assertFalse(body["success"])
        self.assertEqual(body["code"], "precise_code")
        self.assertEqual(body["message"], "A precise, actionable message.")

    def test_error_envelope_carries_a_request_id(self):
        self.assertTrue(self.response.json()["meta"]["request_id"])


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class NoScanSelectedTests(TestCase):
    """Actions that belong to a scan are refused when none is selected.

    List endpoints keep returning an empty result, because "no findings" is a real
    answer for a list. These are the endpoints where the absence is an error, and
    where silence would previously have meant the whole estate instead.
    """

    def setUp(self):
        self.client = Client()  # no session is ever selected

    def test_graph_rebuild_is_refused(self):
        r = self.client.get("/api/graph-index/?rebuild=1")
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.json()["code"], "no_scan_selected")

    def test_graph_correlate_is_refused(self):
        r = self.client.post("/api/graph/correlate/", data="{}", content_type="application/json")
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.json()["code"], "no_scan_selected")

    def test_cbom_export_is_refused(self):
        r = self.client.get("/api/analysis/cbom/?format=ecdat")
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.json()["code"], "no_scan_selected")

    def test_graph_impact_is_refused(self):
        from core.models import WorkSession
        from segments.scraping.discovery.models import GraphNode

        owner = WorkSession.objects.create(name="owns-the-node")
        node = GraphNode.objects.create(
            session=owner, node_type="library", key="k", label="k"
        )
        r = self.client.get(f"/api/graph-index/{node.pk}/impact/?question=blast-radius")
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.json()["code"], "no_scan_selected")

    def test_the_refusal_explains_what_to_do(self):
        body = self.client.get("/api/analysis/cbom/?format=ecdat").json()
        self.assertIn("audit history", body["message"])

    def test_an_unknown_question_is_still_a_400(self):
        """Validation runs before the scope check, so a typo stays a typo."""
        r = self.client.get("/api/graph-index/1/impact/?question=nonsense")
        self.assertEqual(r.status_code, 400)
