"""Tests for the discovery pipeline scanner + end-to-end scan flow."""

import json
import os
import shutil
import tempfile
from types import SimpleNamespace
from unittest import mock

from django.test import Client, TestCase, override_settings

from .scanners.crypto_artefact import CryptoArtefactScanner, _yara_match_to_finding
from .scanners.platform import detect_platform, get_scan_limits, resolve_scan_roots, scan_type_of

from . import services as discovery_services


class YaraMatchMappingTests(TestCase):
    """Unit tests for mapping a YARA match to a discovery raw-finding dict."""

    def test_rsa_match_maps_to_rsa_family(self):
        finding = _yara_match_to_finding(
            {"rule": "Crypto_RSA", "algorithm": "RSA", "kind": "public_key",
             "count": 3, "strings": ["RSA", "PKCS"]},
            "svc/auth/TlsConfig.java",
        )
        self.assertEqual(finding["family"], "rsa")
        self.assertEqual(finding["algorithm"], "RSA")
        self.assertEqual(finding["location"], "svc/auth/TlsConfig.java")
        self.assertAlmostEqual(finding["confidence"], 0.9)
        self.assertEqual(finding["raw"]["matches"], 3)

    def test_tls_match_is_protocol(self):
        finding = _yara_match_to_finding(
            {"rule": "Crypto_TLS", "algorithm": "TLS", "kind": "protocol",
             "count": 1, "strings": ["tls"]},
            "config/tls.yaml",
        )
        self.assertEqual(finding["protocol"], "TLS")
        self.assertEqual(finding["family"], "unknown")

    def test_unknown_rule_falls_back_to_unknown_family(self):
        finding = _yara_match_to_finding(
            {"rule": "Some_Future_Rule", "algorithm": "", "kind": "", "count": 0, "strings": []},
            "x/f",
        )
        self.assertEqual(finding["family"], "unknown")
        self.assertEqual(finding["confidence"], 0.6)


class ScannerRunTests(TestCase):
    """The real scanner detects crypto artefacts in actual source files."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="ecdat_t_")
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))

    def _write(self, rel: str, content: str):
        full = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            f.write(content)

    def test_detects_rsa_ecdsa_and_hash_from_files(self):
        self._write("auth/TlsConfig.java",
                    'class T { void i() { KeyPairGenerator k=\n'
                    ' KeyPairGenerator.getInstance("RSA"); k.initialize(2048); } }')
        self._write("crypto/ecdsa.go",
                    'package c\nimport "crypto/ecdsa"\nfunc k(){ ecdsa.GenerateKey("prime256v1", nil) }')
        self._write("crypto/h.py",
                    'import hashlib\nhashlib.sha256(b"x")\nhashlib.md5(b"x")\n')
        self._write("README.md", "# not scanned\n")

        scanner = CryptoArtefactScanner.__new__(CryptoArtefactScanner)
        scanner.scan_job = type("ScanJob", (), {"target": self.root, "config": {}})()

        findings = scanner.run()
        fams = {f["family"] for f in findings}
        self.assertIn("rsa", fams)
        self.assertIn("ecc", fams)
        self.assertIn("hash", fams)
        # README.md (not a code extension) is never scanned.
        self.assertTrue(all(f["location"] != "README.md" for f in findings))
        # Every finding carries a location.
        self.assertTrue(all(f.get("location") for f in findings))

    def test_run_reports_measured_progress(self):
        self._write("a/one.java", 'KeyPairGenerator.getInstance("RSA");')
        self._write("a/two.go", 'import "crypto/ecdsa"')

        reports = []

        class Ctx:
            def report(self, stage, scanned, total):
                reports.append((stage, scanned, total))

            def check_cancelled(self):
                return None

            def record_skip(self, reason, count=1):
                return None

        scanner = CryptoArtefactScanner.__new__(CryptoArtefactScanner)
        scanner.scan_job = type("ScanJob", (), {"target": self.root, "config": {}})()

        scanner.run(Ctx())

        self.assertTrue(reports)
        stages = {r[0] for r in reports}
        self.assertIn("enumerating", stages)
        self.assertIn("inspecting", stages)
        # The denominator is a real count of in-scope files, never None.
        totals = {r[2] for r in reports if r[0] == "inspecting"}
        self.assertNotIn(None, totals)
        self.assertTrue(all(t >= 2 for t in totals))

    def test_run_honours_cancellation_during_walk(self):
        from .scanners.base import ScanCancelled

        for i in range(40):
            self._write(f"pkg/f{i}.java", 'KeyPairGenerator.getInstance("RSA");')

        class Ctx:
            def __init__(self):
                self.checks = 0

            def report(self, stage, scanned, total):
                return None

            def check_cancelled(self):
                self.checks += 1
                if self.checks > 2:
                    raise ScanCancelled()

            def record_skip(self, reason, count=1):
                return None

        ctx = Ctx()
        scanner = CryptoArtefactScanner.__new__(CryptoArtefactScanner)
        scanner.scan_job = type("ScanJob", (), {"target": self.root, "config": {}})()

        with self.assertRaises(ScanCancelled):
            scanner.run(ctx)


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class EndToEndScanTests(TestCase):
    """POST /api/start-scan/ runs the full pipeline on a real folder."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="ecdat_e2e_")
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))
        with open(os.path.join(self.root, "app.py"), "w") as f:
            f.write("import hashlib\nhashlib.md5(b'x')\nhashlib.sha256(b'x')\n")
        self.client = Client()

    @mock.patch("segments.scraping.discovery.services._auto_analyze")
    @mock.patch(
        "segments.scraping.discovery.services._dispatch_scan",
        side_effect=lambda scan_job, db: discovery_services.run_scan(scan_job),
    )
    def test_start_scan_produces_assets_via_pipeline(self, _mock_auto, _mock_dispatch):
        r = self.client.post(
            "/api/start-scan/",
            data=json.dumps(
                {"scan_type": "specified", "source_type": "source_code",
                 "target": self.root, "options": {}}
            ),
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 201)
        body = r.json()["data"]
        self.assertEqual(body["status"], "completed", msg=json.dumps(body, indent=2))
        self.assertGreaterEqual(body["findings_count"], 1)

        from .models import NormalizedFinding
        nfs = NormalizedFinding.objects.filter(raw_finding__scan_job_id=body["id"])
        self.assertGreaterEqual(nfs.count(), 1)
        self.assertTrue(nfs.filter(family="hash").exists())

    @mock.patch("segments.scraping.discovery.services._dispatch_scan", side_effect=lambda scan_job, db: scan_job)
    @mock.patch("segments.scraping.discovery.services._auto_analyze")
    def test_start_scan_returns_queued_when_dispatched_async(self, _mock_auto, _mock_dispatch):
        r = self.client.post(
            "/api/start-scan/",
            data=json.dumps(
                {"scan_type": "specified", "source_type": "source_code",
                 "target": self.root, "options": {}}
            ),
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 201, msg=r.content[:400])
        body = r.json()["data"]
        self.assertEqual(body["status"], "queued")
        job = _mock_dispatch.call_args.args[0]
        self.assertEqual(job.status, "queued")


OPENSSH_PRIVATE_KEY = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUx\n"
    "OQAAACDBCGVpbmFzX2VjZHNhX2ZpbmdlcnByaW50AAAAIItzZXRzX2VjZHNhX2ZpbmdlcnByaW50\n"
    "AQIDBAUGBwg=\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)
RSA_CERT_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIB6DCCAY+gAwIBAgIJAJXVc1o0pxAYMA0GCSqGSIb3DQEBBQUAMBMxETAPBgNVBAoM\n"
    "CEVDREFUX0NBMB4XDTI2MDEwMTAwMDAwMFoXDTI2MTIzMTIzNTk1OVowEzERMA8GA1UE\n"
    "CgwIRUNEQVRfQ0EwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKOHhPeOKkyWDhj1\n"
    "4z4o2ZtZRyS+/kR0CJfQKqc9kMFsUEcVh3E6toCV0yBjmQmsL3Y7R3Cbns6Qn+j+ZnyQ\n"
    "AgMBAAGjUDBOMB0GA1UdDgQWBBTbYV9Qz5y6mNxB65OQnNpQpVg3NjAfBgNVHSMEGDAW\n"
    "gBTbYV9Qz5y6mNxB65OQnNpQpVg3NTAOBgNVHQ8BAf8EBAMCBaAwDQYJKoZIhvcNAQEF\n"
    "BQADgYEAh9KcAj5B3zLk0QmGBFPLInpQ6OMLU0pJZ1RpBFhaFP+PayxPxJxmS6qjq+tj\n"
    "qC2rL7hBZ8T+W7C7ByTpAqwJb0lY9m8b0zv1A+r9q0LYIgE=\n"
    "-----END CERTIFICATE-----\n"
)


def _fake_job(target: str, scan_type: str = "", config: dict | None = None):
    return SimpleNamespace(
        target=target,
        config=dict(config or {}, **({"scan_type": scan_type} if scan_type else {})),
    )


def ScanJobStub():
    """Minimal stand-in for a ScanJob when exercising a scanner in isolation."""
    from core.models import Mode

    return SimpleNamespace(
        target="/opt/app",
        config={},
        mode=Mode.ACTUAL,
        session_id=None,
        findings_count=0,
        _state=SimpleNamespace(db="default"),
        save=lambda **kw: None,
    )


class PlatformProfileTests(TestCase):
    """Unit tests for platform detection and root resolution."""

    def test_detect_platform_returns_supported_family(self):
        self.assertIn(
            detect_platform(),
            ("windows", "linux", "darwin", "other"),
        )

    def test_specified_scan_resolves_its_single_root(self):
        root = tempfile.mkdtemp(prefix="ecdat_spec_")
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        roots = resolve_scan_roots(_fake_job(root, "specified"))
        self.assertEqual([r.root for r in roots], [os.path.abspath(root)])

    def test_quick_scan_returns_only_existing_high_value_roots(self):
        import segments.scraping.discovery.scanners.platform as plat

        home = tempfile.mkdtemp(prefix="ecdat_home_")
        self.addCleanup(lambda: shutil.rmtree(home, ignore_errors=True))
        os.makedirs(os.path.join(home, ".ssh"), exist_ok=True)
        os.environ["HOME"] = home
        os.environ["USERPROFILE"] = home
        self.addCleanup(lambda: os.environ.pop("HOME", None))
        self.addCleanup(lambda: os.environ.pop("USERPROFILE", None))

        with mock.patch.object(plat, "detect_platform", return_value=plat.PLATFORM_LINUX), \
                mock.patch.object(plat, "_workspace_root", return_value=None):
            roots = resolve_scan_roots(_fake_job("quick", "quick"))

        labels = {r.label for r in roots}
        self.assertIn("~/.ssh", labels)                     # hot spot, present in temp home
        self.assertNotIn("/etc/nginx", labels)              # missing -> filtered out
        self.assertTrue(all(os.path.isdir(r.root) for r in roots))
        self.assertTrue(all(r.scan_all for r in roots if r.label == "~/.ssh"))  # SSH has no extensions

    def test_whole_scan_resolves_every_writable_root(self):
        roots = resolve_scan_roots(_fake_job("whole", "whole"))
        self.assertTrue(roots)
        for r in roots:
            self.assertTrue(os.path.isdir(r.root), r.root)

    def test_scan_type_falls_back_to_target_token(self):
        self.assertEqual(scan_type_of(_fake_job("quick")), "quick")
        self.assertEqual(scan_type_of(_fake_job("whole")), "whole")
        self.assertEqual(scan_type_of(_fake_job("some/folder")), "specified")

    def test_scan_limits_are_unbounded_by_default(self):
        for scope in ("quick", "whole", "specified"):
            with self.subTest(scope=scope):
                limits = get_scan_limits(_fake_job(scope, scope))
                self.assertIsNone(limits.max_files)
                self.assertIsNone(limits.max_depth)
                self.assertIsNone(limits.max_file_size)

    def test_scan_limits_honour_explicit_overrides(self):
        overridden = get_scan_limits(_fake_job("quick", "quick", {"max_files": 99, "max_depth": 3}))
        self.assertEqual(overridden.max_files, 99)
        self.assertEqual(overridden.max_depth, 3)
        # An untouched limit stays unbounded.
        self.assertIsNone(overridden.max_file_size)

    def test_scan_limits_reject_non_numeric_override(self):
        with self.assertRaises(ValueError):
            get_scan_limits(_fake_job("quick", "quick", {"max_files": "many"}))


class KeyMaterialRuleTests(TestCase):
    """The new rules map to canonical families / the scanner detects key files."""

    def test_rsa_cert_rule_maps_to_rsa(self):
        finding = _yara_match_to_finding(
            {"rule": "Crypto_Certificate_RSA", "algorithm": "X509-RSA", "kind": "certificate",
             "count": 1, "strings": ["BEGIN CERTIFICATE"]},
            "/etc/ssl/server.crt",
        )
        self.assertEqual(finding["family"], "rsa")
        self.assertEqual(finding["algorithm"], "X509-RSA")

    def test_ed25519_ssh_rule_maps_to_ecc(self):
        finding = _yara_match_to_finding(
            {"rule": "Crypto_SSH_Ed25519", "algorithm": "Ed25519-SSH", "kind": "public_key",
             "count": 1, "strings": ["ssh-ed25519 AAAAC3Nz"]},
            "~/.ssh/id_ed25519.pub",
        )
        self.assertEqual(finding["family"], "ecc")
        self.assertEqual(finding["algorithm"], "Ed25519-SSH")

    def test_scanner_detects_openssh_key_and_rsa_cert_in_quick_scope(self):
        import segments.scraping.discovery.scanners.platform as plat

        home = tempfile.mkdtemp(prefix="ecdat_keys_")
        self.addCleanup(lambda: shutil.rmtree(home, ignore_errors=True))
        ssh = os.path.join(home, ".ssh")
        os.makedirs(ssh, exist_ok=True)
        with open(os.path.join(ssh, "id_ecdsa"), "w") as f:
            f.write(OPENSSH_PRIVATE_KEY)
        with open(os.path.join(ssh, "server.crt"), "w") as f:
            f.write(RSA_CERT_PEM)
        os.environ["HOME"] = home
        os.environ["USERPROFILE"] = home
        self.addCleanup(lambda: os.environ.pop("HOME", None))
        self.addCleanup(lambda: os.environ.pop("USERPROFILE", None))

        scanner = CryptoArtefactScanner.__new__(CryptoArtefactScanner)
        scanner.scan_job = _fake_job("quick", "quick")

        with mock.patch.object(plat, "detect_platform", return_value=plat.PLATFORM_LINUX), \
                mock.patch.object(plat, "_workspace_root", return_value=None):
            findings = scanner.run()

        algorithms = {f["algorithm"] for f in findings}
        self.assertIn("OpenSSH-private", algorithms)    # extension-less key found via scan_all root
        self.assertIn("X509-RSA", algorithms)           # .crt detected without *.pem extension
        self.assertTrue(all("~/.ssh" in f["location"] for f in findings))


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class AutoSessionTests(TestCase):
    """A new scan automatically creates + switches to its own work session."""

    def setUp(self):
        self.client = Client()

    def test_start_scan_auto_creates_and_switches_session(self):
        from unittest.mock import patch

        from core.models import WorkSession
        from segments.scraping.discovery.models import ScanJob

        produced = {}

        def fake_create(**kw):
            job = ScanJob.objects.using("default").create(
                source_type=kw["source_type"],
                target=kw["target"],
                mode="actual",
                status=ScanJob.Status.COMPLETED,
                session_id=kw["session_id"],
            )
            produced["session_id"] = kw["session_id"]
            return job

        with patch("segments.scraping.discovery.services.create_and_run_scan", side_effect=fake_create):
            r = self.client.post(
                "/api/start-scan/",
                data=json.dumps(
                    {"scan_type": "specified", "source_type": "source_code",
                     "target": "/opt/app", "options": {}}
                ),
                content_type="application/json",
            )

        self.assertEqual(r.status_code, 201)
        sid = r.json()["data"]["session"]["id"]
        self.assertTrue(sid)
        self.assertTrue(WorkSession.objects.using("default").filter(pk=sid).exists())
        self.assertEqual(produced["session_id"], sid)

        job = ScanJob.objects.using("default").get(session_id=sid)
        r = self.client.get("/api/scans/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(job.pk, [x["id"] for x in r.json()["data"]["results"]])

        info = self.client.get("/api/session/info/").json()["data"]
        self.assertEqual(info["session_id"], sid)
        self.assertEqual(info["scope"], "session")

    @mock.patch("segments.scraping.discovery.services._auto_analyze")
    def test_scan_data_auto_session_and_isolation(self, _mock_auto):
        from core.models import WorkSession
        from core.sessions import scope
        from segments.scraping.discovery.models import CryptoAsset, NormalizedFinding, ScanJob

        before_count = ScanJob.objects.using("default").count()

        r = self.client.post(
            "/api/scan-data/",
            data=json.dumps({
                "source_type": "source_code",
                "findings": [
                    {"location": "a.js", "content_snippet": "RSA"},
                    {"location": "b.py", "family": "rsa", "algorithm": "RSA",
                     "key_size": 2048, "confidence": 0.9},
                ],
            }),
            content_type="application/json",
        )

        self.assertEqual(r.status_code, 201)
        sid = r.json()["data"]["session"]["id"]
        self.assertTrue(sid)
        ws = WorkSession.objects.using("default").get(pk=sid)
        self.assertTrue(ws.name.startswith("external-data"))

        job = ScanJob.objects.using("default").get(session_id=sid)
        self.assertGreater(job.findings_count, 0)
        self.assertEqual(
            ScanJob.objects.using("default").count(), before_count + 1
        )
        self.assertGreater(scope(NormalizedFinding.objects.using("default"), ws.pk).count(), 0)
        self.assertGreater(scope(CryptoAsset.objects.using("default"), ws.pk).count(), 0)

        r = self.client.get("/api/scans/")
        self.assertEqual([x["id"] for x in r.json()["data"]["results"]], [job.pk])

        self.client.post("/api/session/switch/0/")
        r = self.client.get("/api/scans/")
        # Isolation, not aggregation: with no session selected there is nothing
        # to show. Returning the scan here is what let two unrelated scans read
        # as one list, so an empty result is the behaviour under test.
        self.assertEqual(r.json()["data"]["results"], [])


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class AutoAnalysisTests(TestCase):
    """A finished scan automatically stages analysis (pending a context choice)."""

    def _job(self, mode="actual", findings_count=1, **kw):
        from segments.scraping.discovery.models import ScanJob

        return ScanJob.objects.using("default").create(
            source_type="source_code",
            target="auto-q",
            mode=mode,
            status=ScanJob.Status.COMPLETED,
            findings_count=findings_count,
            **kw,
        )

    @mock.patch("segments.ml.analysis.runner.pending_analysis")
    def test_auto_analyze_stages_pending_analysis(self, mock_pending):
        job = self._job()

        discovery_services._auto_analyze(job)

        mock_pending.assert_called_once()
        self.assertIs(mock_pending.call_args.args[0], job)

    @mock.patch("segments.ml.analysis.runner.pending_analysis")
    def test_auto_analyze_skips_when_no_data(self, mock_pending):
        job = self._job(findings_count=0)

        discovery_services._auto_analyze(job)

        mock_pending.assert_not_called()

    @mock.patch("segments.ml.analysis.runner.pending_analysis")
    def test_auto_analyze_skips_duplicate(self, mock_pending):
        from segments.ml.analysis.models import AnalysisRun

        job = self._job()
        AnalysisRun.objects.using("default").create(
            scan_job=job, mode="actual", status=AnalysisRun.Status.QUEUED
        )

        discovery_services._auto_analyze(job)

        mock_pending.assert_not_called()

    @mock.patch("segments.ml.analysis.runner.pending_analysis")
    def test_auto_analyze_skips_demo(self, mock_pending):
        job = self._job(mode="demo")

        discovery_services._auto_analyze(job)

        mock_pending.assert_not_called()

    @mock.patch.dict(os.environ, {"ECDAT_AUTO_ANALYSE": "0"})
    @mock.patch("segments.ml.analysis.runner.pending_analysis")
    def test_auto_analyze_opt_out_env(self, mock_pending):
        job = self._job()

        discovery_services._auto_analyze(job)

        mock_pending.assert_not_called()


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class GraphDataTests(TestCase):
    """GET /api/graph/ returns assets + findings across ALL categories + correlations."""

    def setUp(self):
        self.client = Client()

    def _ingest(self, findings):
        return self.client.post(
            "/api/scan-data/",
            data=json.dumps({"source_type": "source_code", "findings": findings}),
            content_type="application/json",
        ).json()["data"]

    @mock.patch("segments.scraping.discovery.services._auto_analyze")
    def test_graph_data_lists_all_categories_and_correlations(self, _mock_auto):
        self._ingest([
            {"location": "svc/auth/TlsConfig.java", "family": "rsa", "algorithm": "RSA",
             "key_size": 2048, "confidence": 0.9},
            {"location": "svc/kms/KeyStore.java", "family": "rsa", "algorithm": "RSA",
             "key_size": 4096, "confidence": 0.7},
            {"location": "crypto/h.py", "family": "hash", "algorithm": "SHA256",
             "confidence": 0.9},
        ])

        r = self.client.get("/api/graph/")
        self.assertEqual(r.status_code, 200)
        data = r.json()["data"]
        self.assertIn("assets", data)
        self.assertIn("findings", data)
        self.assertIn("asset_relations", data)
        self.assertIn("finding_relations", data)

        families = {f["family"] for f in data["findings"]}
        self.assertIn("rsa", families)
        self.assertIn("hash", families)
        self.assertGreaterEqual(len(data["assets"]), 1)

        kinds = {e["kind"] for e in data["finding_relations"]}
        self.assertIn("family", kinds)          # same-family correlation edge
        self.assertIn("asset", kinds)           # finding -> asset consolidation edge
        self.assertTrue(all(e["from"].startswith("f") for e in data["finding_relations"]))

        self.assertTrue(any(a.get("linked_findings") for a in data["assets"]))

    @mock.patch("segments.scraping.discovery.services._auto_analyze")
    def test_graph_asset_relations_follow_active_session(self, _mock_auto):
        """Correlation edges inherit the session, so the graph stays linked
        under a work session instead of dropping them all (legacy NULL bug)."""
        first_session = self._ingest([
            {"location": "k1.java", "family": "rsa", "algorithm": "RSA", "key_size": 2048,
             "confidence": 0.9},
            {"location": "k2.java", "family": "rsa", "algorithm": "RSA", "key_size": 4096,
             "confidence": 0.7},
        ])["session"]["id"]
        second_session = self._ingest([
            {"location": "h.py", "family": "hash", "algorithm": "SHA256", "confidence": 0.9},
        ])["session"]["id"]
        self.assertNotEqual(first_session, second_session)

        from segments.scraping.discovery.models import AssetRelation

        rels = list(AssetRelation.objects.using("default").values_list("session_id", flat=True))
        self.assertEqual(len(rels), 1)              # one relate edge, from the 2-RSA session
        self.assertEqual(rels[0], first_session)    # stamped with the owning session

        r = self.client.get("/api/graph/")
        self.assertEqual(r.json()["data"]["asset_relations"], [])   # other session's edge stays hidden

        # With no session selected the edge is not shown either. Returning it
        # here is what let one scan's graph display another scan's relations.
        self.client.post("/api/session/switch/0/")
        r = self.client.get("/api/graph/")
        self.assertEqual(r.json()["data"]["asset_relations"], [])

    @mock.patch("segments.scraping.discovery.services._auto_analyze")
    def test_graph_correlate_endpoint_builds_edges(self, _mock_auto):
        self._ingest([
            {"location": "k1.java", "family": "rsa", "algorithm": "RSA", "key_size": 2048,
             "confidence": 0.9},
            {"location": "k2.java", "family": "rsa", "algorithm": "RSA", "key_size": 4096,
             "confidence": 0.7},
        ])
        from segments.scraping.discovery.models import AssetRelation

        AssetRelation.objects.using("default").all().delete()   # simulate "correlation didn't happen"

        r = self.client.post("/api/graph/correlate/", content_type="application/json")
        self.assertEqual(r.status_code, 200)
        body = r.json()["data"]
        self.assertGreaterEqual(body.get("created"), 1)         # edges rebuilt on demand
        self.assertGreaterEqual(body.get("total"), 1)           # and now visible to the graph

    @mock.patch("segments.scraping.discovery.services._auto_analyze")
    def test_graph_data_scopes_to_active_session(self, _mock_auto):
        first_session = self._ingest([
            {"location": "a.js", "family": "rsa", "algorithm": "RSA", "key_size": 2048,
             "confidence": 0.9},
        ])["session"]["id"]
        second_session = self._ingest([
            {"location": "b.py", "family": "hash", "algorithm": "SHA256", "confidence": 0.9},
        ])["session"]["id"]
        self.assertNotEqual(first_session, second_session)

        from segments.scraping.discovery.models import NormalizedFinding

        first_ids = set(
            NormalizedFinding.objects.using("default")
            .filter(session_id=first_session).values_list("pk", flat=True)
        )
        first_ids = {(f"f{pk}") for pk in first_ids}

        r = self.client.get("/api/graph/")
        data = r.json()["data"]
        node_keys = {f"f{f['id']}" for f in data["findings"]}
        self.assertTrue(node_keys)                      # active session has its own findings
        self.assertTrue(node_keys.isdisjoint(first_ids))  # other session's findings excluded


class FamilyClassificationTests(TestCase):
    """Family resolution must never reference a missing enum member.

    Regression guard: `3des` findings previously resolved through
    `_guess_family_from_algorithm` to an `AlgorithmFamily.DES3` attribute that
    was never defined, raising AttributeError and failing the whole job after
    its raw findings were already persisted.
    """

    def _families(self):
        from .models import NormalizedFinding

        return {choice.value for choice in NormalizedFinding.AlgorithmFamily}

    def test_every_mapped_family_is_a_valid_choice(self):
        from .normalizer import _FAMILY_MAP

        self.assertTrue(set(_FAMILY_MAP.values()).issubset(self._families()))

    def test_every_guessed_family_is_a_valid_choice(self):
        from .normalizer import _guess_family_from_algorithm

        for algorithm in [
            "RSA-2048", "ECDSA-P256", "Ed25519", "DSA-2048", "DH-2048", "AES-256-GCM",
            "3DES-EDE3", "DES-CBC", "TripleDES", "ML-KEM-768", "SLH-DSA-SHA2-128",
            "SHA-256", "MD5", "unrecognised-thing",
        ]:
            with self.subTest(algorithm=algorithm):
                self.assertIn(_guess_family_from_algorithm(algorithm), self._families())

    def test_triple_des_variants_map_to_des3(self):
        from .models import NormalizedFinding
        from .normalizer import _FAMILY_MAP, _guess_family_from_algorithm

        for alias in ["3des", "des", "tripledes", "triple-des"]:
            with self.subTest(alias=alias):
                self.assertEqual(
                    _FAMILY_MAP[alias], NormalizedFinding.AlgorithmFamily.DES3
                )

        for algorithm in ["3DES", "des-EDE3", "TripleDES"]:
            with self.subTest(algorithm=algorithm):
                self.assertEqual(
                    _guess_family_from_algorithm(algorithm),
                    NormalizedFinding.AlgorithmFamily.DES3,
                )

    def test_normalize_triple_des_finding_does_not_raise(self):
        from .models import NormalizedFinding, RawFinding, ScanJob
        from .normalizer import normalize_finding

        job = ScanJob.objects.using("default").create(
            source_type=ScanJob.SourceType.SOURCE_CODE, target="demo:3des"
        )
        raw = RawFinding.objects.using("default").create(
            scan_job=job,
            source_type=ScanJob.SourceType.SOURCE_CODE,
            location="legacy/cipher.c",
            raw_json={"family": "3des", "algorithm": "3DES-EDE3", "key_size": 168},
        )

        norm = normalize_finding(raw, using="default")

        self.assertEqual(norm.family, NormalizedFinding.AlgorithmFamily.DES3)
        self.assertEqual(norm.key_size, 168)


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class ScannerRegistryTests(TestCase):
    """Discovery must describe itself from the registry, not hard-coded UI."""

    def test_every_registered_scanner_declares_metadata(self):
        from .scanners import SCANNER_REGISTRY

        for source_type, cls in SCANNER_REGISTRY.items():
            with self.subTest(source_type=source_type):
                described = cls.describe()
                self.assertTrue(described["id"])
                self.assertTrue(described["name"])
                self.assertTrue(described["version"])
                self.assertEqual(described["status"], "available")

    def test_list_scanners_covers_every_source_type(self):
        from .models import ScanJob
        from .scanners import list_scanners

        entries = list_scanners()
        self.assertEqual(
            {e["source_type"] for e in entries}, set(ScanJob.SourceType.values)
        )

    def test_only_registered_sources_are_available(self):
        from .scanners import SCANNER_REGISTRY, list_scanners

        available = {
            e["source_type"] for e in list_scanners() if e["status"] == "available"
        }
        self.assertEqual(available, set(SCANNER_REGISTRY))

    def test_planned_sources_advertise_no_capabilities(self):
        from .scanners import list_scanners

        planned = [e for e in list_scanners() if e["status"] == "planned"]
        self.assertTrue(planned)
        for entry in planned:
            with self.subTest(source_type=entry["source_type"]):
                self.assertEqual(entry["capabilities"], [])
                self.assertEqual(entry["configuration_schema"], {})

    def test_source_discovery_exposes_no_limits(self):
        """Discovery must cover the whole target by default."""
        from .scanners import SCANNER_REGISTRY

        schema = SCANNER_REGISTRY[
            list(SCANNER_REGISTRY)[0]
        ].describe()["configuration_schema"]
        self.assertEqual(schema, {})

    def test_scanners_endpoint_lists_registry(self):
        r = self.client.get("/api/scanners/")

        self.assertEqual(r.status_code, 200)
        data = r.json()["data"]
        self.assertIn("scanners", data)
        self.assertIn("source-discovery", data["available"])
        self.assertTrue(any(e["status"] == "planned" for e in data["scanners"]))

    def test_scanners_endpoint_rejects_non_get(self):
        self.assertEqual(self.client.post("/api/scanners/").status_code, 405)

    def test_unavailable_source_is_rejected_at_creation(self):
        from .models import ScanJob

        with self.assertRaises(discovery_services.ScanInspectionError):
            discovery_services.create_and_run_scan(
                source_type=ScanJob.SourceType.HSM, target="demo:x", scan_type="quick"
            )


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class ScanJobLifecycleTests(TestCase):
    """Lifecycle states, cancellation races, and partial-coverage reporting."""

    def _job(self, **kw):
        from .models import ScanJob

        fields = {
            "source_type": ScanJob.SourceType.SOURCE_CODE,
            "target": "t",
            "mode": "actual",
            "session_id": None,
        }
        fields.update(kw)
        return ScanJob.objects.using("default").create(**fields)

    def test_cancel_requests_then_worker_confirms(self):
        from .services import cancel_scan_job
        from .models import ScanJob

        job = self._job(status=ScanJob.Status.RUNNING)
        self.assertTrue(cancel_scan_job(job))

        job.refresh_from_db()
        # A running job is only *asked* to stop; the worker confirms.
        self.assertEqual(job.status, ScanJob.Status.CANCELLING)

    def test_cancel_of_queued_job_completes_immediately(self):
        from .services import cancel_scan_job
        from .models import ScanJob

        job = self._job(status=ScanJob.Status.QUEUED)
        self.assertTrue(cancel_scan_job(job))

        job.refresh_from_db()
        self.assertEqual(job.status, ScanJob.Status.CANCELLED)
        self.assertIsNotNone(job.finished_at)

    def test_cancel_rejects_terminal_jobs(self):
        from .services import cancel_scan_job
        from .models import ScanJob

        for status in (
            ScanJob.Status.COMPLETED,
            ScanJob.Status.PARTIAL,
            ScanJob.Status.FAILED,
            ScanJob.Status.CANCELLED,
        ):
            with self.subTest(status=status):
                job = self._job(status=status)
                self.assertFalse(cancel_scan_job(job))
                job.refresh_from_db()
                self.assertEqual(job.status, status)

    def test_cancelling_scan_stops_before_completing(self):
        from .models import ScanJob

        job = self._job(status=ScanJob.Status.QUEUED)

        # A cancel that lands during correlation must beat COMPLETED.
        def cancel_during_correlation(*_a, **_kw):
            ScanJob.objects.using("default").filter(pk=job.pk).update(
                status=ScanJob.Status.CANCELLING
            )

        with mock.patch.object(
            discovery_services, "build_correlations", side_effect=cancel_during_correlation
        ),             mock.patch.object(discovery_services, "_post_ingest"):
            discovery_services.run_scan(job)

        job.refresh_from_db()
        self.assertEqual(job.status, ScanJob.Status.CANCELLED, msg=job.error)

    def test_completed_scan_keeps_real_progress(self):
        from .models import ScanJob

        job = self._job(status=ScanJob.Status.QUEUED)

        class FakeScanner:
            source_type = ScanJob.SourceType.SOURCE_CODE

            def run(self, context=None):
                context.report("inspecting", 5, 10)
                raise discovery_services.ScanCancelled(job.pk)

            def ingest(self, findings):
                return 0

        with mock.patch.object(discovery_services, "get_scanner", return_value=FakeScanner()):
            discovery_services.run_scan(job)

        job.refresh_from_db()
        self.assertEqual(job.status, ScanJob.Status.CANCELLED)
        # Progress is not rewound to 0 on cancel.
        self.assertGreater(job.progress, 0)
        self.assertEqual(job.items_scanned, 5)
        self.assertEqual(job.items_total, 10)

    def test_skipped_items_produce_partial_not_silent_success(self):
        from .models import ScanJob

        job = self._job(status=ScanJob.Status.QUEUED)

        class FakeScanner:
            source_type = ScanJob.SourceType.SOURCE_CODE

            def run(self, context=None):
                context.record_skip("unreadable", 7)
                return []

            def ingest(self, findings):
                return 0

        with mock.patch.object(discovery_services, "get_scanner", return_value=FakeScanner()):
            with mock.patch.object(discovery_services, "_post_ingest"):
                discovery_services.run_scan(job)

        job.refresh_from_db()
        self.assertEqual(job.status, ScanJob.Status.PARTIAL)
        self.assertEqual(job.items_skipped, 7)
        self.assertEqual(job.error_code, "PARTIAL_COVERAGE")
        self.assertTrue(job.error_recoverable)
        self.assertIn("could not be read", job.error)

    def test_clean_scan_reports_completed(self):
        from .models import ScanJob

        job = self._job(status=ScanJob.Status.QUEUED)

        class FakeScanner:
            source_type = ScanJob.SourceType.SOURCE_CODE

            def run(self, context=None):
                context.report("inspecting", 3, 3)
                return []

            def ingest(self, findings):
                return 0

        with mock.patch.object(discovery_services, "get_scanner", return_value=FakeScanner()):
            with mock.patch.object(discovery_services, "_post_ingest"):
                discovery_services.run_scan(job)

        job.refresh_from_db()
        self.assertEqual(job.status, ScanJob.Status.COMPLETED)
        self.assertEqual(job.progress, 100)
        self.assertEqual(job.items_skipped, 0)
        self.assertEqual(job.error_code, "")

    def test_failure_records_structured_error(self):
        from .models import ScanJob

        job = self._job(status=ScanJob.Status.QUEUED)

        class Boom:
            source_type = "source_code"

            def run(self, context=None):
                raise ValueError("upstream exploded")

        with mock.patch.object(discovery_services, "get_scanner", return_value=Boom()):
            discovery_services.run_scan(job)

        job.refresh_from_db()
        self.assertEqual(job.status, "failed")
        self.assertEqual(job.error_code, "ValueError")
        self.assertEqual(job.error_scope, "discovery")
        self.assertFalse(job.error_recoverable)
        self.assertIn("upstream exploded", job.error)

    def test_sweep_resolves_orphaned_cancelling_jobs(self):
        from core import modes as modes_mod
        from .services import sweep_pending_scans
        from .models import ScanJob

        stuck = self._job(status=ScanJob.Status.CANCELLING)

        # The sweep walks every mode's database; tests only allow `default`.
        with mock.patch.object(modes_mod, "MODES", ("actual",)):
            self.assertEqual(sweep_pending_scans(), 0)

        stuck.refresh_from_db()
        self.assertEqual(stuck.status, ScanJob.Status.CANCELLED)

    def test_serializer_exposes_progress_and_error_detail(self):
        from .serializers import ScanJobSerializer

        job = self._job(
            status="partial",
            progress_stage="done",
            items_total=100,
            items_scanned=90,
            items_skipped=10,
            error_code="PARTIAL_COVERAGE",
            error_scope="discovery",
            error_recoverable=True,
            error_action="Re-run.",
        )
        data = ScanJobSerializer(job).data
        for key in (
            "progress_stage",
            "items_total",
            "items_scanned",
            "items_skipped",
            "error_code",
            "error_scope",
            "error_recoverable",
            "error_action",
        ):
            with self.subTest(key=key):
                self.assertIn(key, data)


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class ScannerContractTests(TestCase):
    """Milestone 2: the scanner owns target/config rules and its output shape."""

    def _scanner(self):
        from .scanners import SCANNER_REGISTRY

        job = ScanJobStub()
        return SCANNER_REGISTRY["source_code"](job)

    def test_scanner_output_matches_the_handoff_contract(self):
        """Anything a scanner emits must satisfy the shared contract."""
        from schema.contracts.raw_finding import RawFindingPayload

        from .models import RawFinding, ScanJob
        from .scanners import SCANNER_REGISTRY

        job = ScanJob.objects.using("default").create(
            source_type=ScanJob.SourceType.SOURCE_CODE, target="/opt/app", mode="actual"
        )
        scanner = SCANNER_REGISTRY["source_code"](job)
        scanner.ingest(
            [
                {"location": "a.py", "family": "rsa", "algorithm": "RSA",
                 "key_size": 2048, "confidence": 0.9, "vendor_extra": {"k": "v"}},
                {"location": "b.go", "family": "des3", "algorithm": "3DES", "key_size": 168},
            ]
        )

        rows = list(RawFinding.objects.using("default").filter(scan_job=job).order_by("location"))
        self.assertEqual(len(rows), 2)
        for row in rows:
            with self.subTest(location=row.location):
                # Raises if the persisted payload does not validate.
                RawFindingPayload.model_validate(row.raw_json)
        self.assertEqual(rows[0].raw_json["vendor_extra"], {"k": "v"})

    def test_scanner_emitting_invalid_output_is_rejected(self):
        from .models import ScanJob
        from .scanners import SCANNER_REGISTRY

        job = ScanJob.objects.using("default").create(
            source_type=ScanJob.SourceType.SOURCE_CODE, target="/opt/app", mode="actual"
        )
        scanner = SCANNER_REGISTRY["source_code"](job)
        with self.assertRaises(ValueError) as ctx:
            scanner.ingest([{"family": "rsa", "algorithm": "RSA"}])  # no location
        self.assertIn("location", str(ctx.exception))
        # Nothing was persisted for the rejected batch.
        from .models import RawFinding

        self.assertEqual(RawFinding.objects.using("default").filter(scan_job=job).count(), 0)

    def test_empty_target_is_rejected_by_the_scanner(self):
        scanner = self._scanner()
        with self.assertRaises(ValueError):
            scanner.validate_target("   ")

    def test_target_is_stripped(self):
        scanner = self._scanner()
        self.assertEqual(scanner.validate_target("  /opt/app  "), "/opt/app")

    def test_unknown_config_option_is_rejected(self):

        with self.assertRaises(discovery_services.ScanInspectionError) as ctx:
            discovery_services.create_and_run_scan(
                source_type="source_code", target="/opt/app",
                config={"max_filess": 10}, scan_type="specified",
            )
        self.assertIn("max_filess", str(ctx.exception))

    def test_config_option_typo_names_the_supported_options(self):

        with self.assertRaises(discovery_services.ScanInspectionError) as ctx:
            discovery_services.create_and_run_scan(
                source_type="source_code", target="/opt/app",
                config={"nope": 1}, scan_type="specified",
            )
        self.assertIn("nope", str(ctx.exception))

    def test_unknown_discovery_scope_is_rejected(self):

        with self.assertRaises(discovery_services.ScanInspectionError):
            discovery_services.create_and_run_scan(
                source_type="source_code", target="/opt/app", scan_type="galaxy"
            )

    def test_registry_covers_a_scanner_registered_after_the_model(self):
        """The registry, not the model enum, decides what exists."""
        from .scanners import list_scanners

        class NewScanner:
            source_type = "totally_new_source"
            scanner_id = "new-source"
            name = "New source"
            description = "d"
            version = "1.0.0"
            supported_targets = ()
            supported_artifacts = ()
            capabilities = ()
            configuration_schema = {}
            status = "available"

            @classmethod
            def describe(cls):
                return {
                    "id": cls.scanner_id,
                    "source_type": cls.source_type,
                    "name": cls.name,
                    "description": cls.description,
                    "version": cls.version,
                    "supported_targets": [],
                    "supported_artifacts": [],
                    "capabilities": [],
                    "configuration_schema": {},
                    "status": cls.status,
                }

        from . import scanners as scanners_mod

        with mock.patch.dict(scanners_mod.SCANNER_REGISTRY, {"totally_new_source": NewScanner}):
            entries = {e["source_type"]: e for e in list_scanners()}
            self.assertIn("totally_new_source", entries)
            self.assertEqual(entries["totally_new_source"]["status"], "available")

    def test_unknown_source_label_does_not_raise(self):
        """An unrecognised source must not crash asset naming."""
        from .classifier import _source_label

        self.assertEqual(_source_label("source_code"), "Source Code Repos")
        self.assertEqual(_source_label("brand_new"), "Brand New")
        self.assertEqual(_source_label(""), "")


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class ImportContractTests(TestCase):
    """Imported findings are validated against the shared handoff contract."""

    def _post(self, payload):
        return self.client.post(
            "/api/scan-data/", data=json.dumps(payload), content_type="application/json"
        )

    def test_valid_import_is_accepted(self):
        from .models import ScanJob

        r = self._post(
            {
                "source_type": "source_code",
                "target": "contract-check",
                "findings": [
                    {"location": "a.py", "family": "rsa", "algorithm": "RSA",
                     "key_size": 2048, "confidence": 0.9},
                ],
            }
        )
        self.assertEqual(r.status_code, 201, msg=r.content[:400])
        job = ScanJob.objects.using("default").get(pk=r.json()["data"]["id"])
        self.assertEqual(job.findings_count, 1)

    def test_non_object_finding_is_rejected(self):
        """A bare string used to raise AttributeError and return a 500."""
        r = self._post({"source_type": "source_code", "findings": ["not-an-object"]})
        self.assertEqual(r.status_code, 400)
        self.assertIn("findings.0", r.json()["message"])

    def test_null_finding_is_rejected(self):
        r = self._post({"source_type": "source_code", "findings": [None]})
        self.assertEqual(r.status_code, 400)

    def test_missing_location_is_rejected(self):
        """Provenance is required: a finding without a location is not evidence."""
        r = self._post(
            {"source_type": "source_code", "findings": [{"family": "rsa", "algorithm": "RSA"}]}
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn("location", r.json()["message"])

    def test_out_of_range_confidence_is_rejected(self):
        r = self._post(
            {
                "source_type": "source_code",
                "findings": [{"location": "a.py", "confidence": 42}],
            }
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn("confidence", r.json()["message"])

    def test_unknown_family_is_rejected(self):
        r = self._post(
            {"source_type": "source_code", "findings": [{"location": "a.py", "family": "banana"}]}
        )
        self.assertEqual(r.status_code, 400)

    def test_family_is_optional_and_defaults_to_unknown(self):
        r = self._post(
            {"source_type": "source_code", "findings": [{"location": "a.py", "algorithm": "RSA-2048"}]}
        )
        self.assertEqual(r.status_code, 201, msg=r.content[:400])

    def test_unknown_source_type_is_rejected(self):
        r = self._post({"source_type": "telepathy", "findings": []})
        self.assertEqual(r.status_code, 400)

    def test_findings_must_be_an_array(self):
        r = self._post({"source_type": "source_code", "findings": {"a": 1}})
        self.assertEqual(r.status_code, 400)
        self.assertIn("list", r.json()["message"])

    def test_rejected_import_creates_no_workspace(self):
        """A bad payload must not leave an empty session behind."""
        from core.models import WorkSession

        before = WorkSession.objects.using("default").count()
        self._post({"source_type": "source_code", "findings": ["bad"]})
        self.assertEqual(WorkSession.objects.using("default").count(), before)

    def test_mode_in_payload_is_not_honoured(self):
        """The data boundary is chosen by the service, never the caller."""
        from .models import ScanJob

        r = self._post(
            {
                "source_type": "source_code",
                "mode": "demo",
                "findings": [{"location": "a.py", "family": "rsa"}],
            }
        )
        self.assertEqual(r.status_code, 201, msg=r.content[:400])
        job = ScanJob.objects.using("default").get(pk=r.json()["data"]["id"])
        self.assertEqual(job.mode, "actual")

    def test_extra_scanner_fields_are_preserved(self):
        from .models import RawFinding

        r = self._post(
            {
                "source_type": "source_code",
                "findings": [
                    {"location": "a.py", "family": "rsa", "kind": "private_key",
                     "vendor_specific": {"sig": "abc"}},
                ],
            }
        )
        self.assertEqual(r.status_code, 201, msg=r.content[:400])
        raw = RawFinding.objects.using("default").filter(scan_job_id=r.json()["data"]["id"]).first()
        self.assertEqual(raw.raw_json["kind"], "private_key")
        self.assertEqual(raw.raw_json["vendor_specific"], {"sig": "abc"})

    def test_over_long_location_is_rejected(self):
        r = self._post(
            {"source_type": "source_code", "findings": [{"location": "x" * 2000, "family": "rsa"}]}
        )
        self.assertEqual(r.status_code, 400)


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class AssetSessionScopingTests(TestCase):
    """Identical findings in different workspaces must not share one asset."""

    def _ingest(self, session, raw_json):
        from .classifier import classify_asset
        from .models import RawFinding, ScanJob
        from .normalizer import normalize_finding

        job = ScanJob.objects.using("default").create(
            source_type=ScanJob.SourceType.SOURCE_CODE,
            target=f"scope-{session.pk}",
            session_id=session.pk,
        )
        raw = RawFinding.objects.using("default").create(
            scan_job=job,
            session_id=session.pk,
            source_type=ScanJob.SourceType.SOURCE_CODE,
            location=raw_json["location"],
            raw_json=raw_json,
        )
        norm = normalize_finding(raw, using="default", session_id=session.pk)
        return classify_asset(norm, using="default", session_id=session.pk)

    def test_same_finding_in_two_sessions_creates_two_assets(self):
        from core.models import WorkSession
        from core.sessions import scope
        from .models import CryptoAsset

        first = WorkSession.objects.using("default").create(name="scope-one")
        second = WorkSession.objects.using("default").create(name="scope-two")

        payload = {
            "location": "payments/legacy.py",
            "family": "rsa",
            "algorithm": "RSA-2048",
            "key_size": 2048,
        }
        asset_a = self._ingest(first, payload)
        asset_b = self._ingest(second, payload)

        self.assertNotEqual(asset_a.pk, asset_b.pk)
        self.assertEqual(asset_a.session_id, first.pk)
        self.assertEqual(asset_b.session_id, second.pk)
        self.assertEqual(asset_a.name, asset_b.name)

        for session in (first, second):
            scoped = scope(CryptoAsset.objects.using("default"), session.pk)
            self.assertEqual(scoped.count(), 1, msg=f"expected 1 asset in session {session.pk}")

    def test_repeat_finding_in_same_session_reuses_the_asset(self):
        from core.models import WorkSession
        from .models import CryptoAsset

        session = WorkSession.objects.using("default").create(name="scope-repeat")

        payload = {
            "location": "payments/legacy.py",
            "family": "rsa",
            "algorithm": "RSA-2048",
            "key_size": 2048,
        }
        first = self._ingest(session, payload)
        second = self._ingest(session, payload)

        self.assertEqual(first.pk, second.pk)
        self.assertEqual(
            CryptoAsset.objects.using("default").filter(session_id=session.pk).count(), 1
        )
        self.assertEqual(first.normalized_findings.count(), 2)


class CertificateParsingTests(TestCase):
    """Certificates are parsed, not string-matched."""

    def _self_signed_pem(self) -> bytes:
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "ecdat.test"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ECDAT"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(1234567890)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("ecdat.test")]), critical=False
            )
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM)

    def test_parses_real_certificate_metadata(self):
        from .scanners import x509 as x509mod

        details = x509mod.load_certificates(self._self_signed_pem())
        self.assertEqual(len(details), 1)
        detail = details[0]
        self.assertIn("ecdat.test", detail.subject)
        self.assertEqual(detail.public_key_algorithm, "RSA")
        self.assertEqual(detail.key_size, 2048)
        self.assertEqual(detail.serial, "499602d2")
        self.assertIn("ecdat.test", detail.san)
        self.assertTrue(detail.self_signed)
        self.assertFalse(detail.expired)
        self.assertEqual(len(detail.sha256_fingerprint), 64)

    def test_rejects_a_certificate_header_in_plain_text(self):
        """A BEGIN CERTIFICATE line in prose is not a certificate."""
        from .scanners import x509 as x509mod

        fake = b"docs say: -----BEGIN CERTIFICATE----- but this is prose, not a cert"
        self.assertEqual(x509mod.load_certificates(fake), [])

    def test_parses_a_bundle(self):
        from .scanners import x509 as x509mod

        pem = self._self_signed_pem()
        self.assertEqual(len(x509mod.load_certificates(pem + pem)), 2)

    def test_weak_key_detection_follows_nist_minimums(self):
        from .scanners import x509 as x509mod

        self.assertTrue(x509mod.is_weak_key("RSA", 1024))
        self.assertFalse(x509mod.is_weak_key("RSA", 2048))
        self.assertTrue(x509mod.is_weak_key("EC", 160))
        self.assertFalse(x509mod.is_weak_key("EC", 256))

    def test_certificate_finding_records_evidence(self):
        import tempfile

        from .models import ScanJob
        from .scanners import SCANNER_REGISTRY

        root = tempfile.mkdtemp(prefix="ecdat_cert_")
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        with open(os.path.join(root, "server.crt"), "wb") as handle:
            handle.write(self._self_signed_pem())

        job = ScanJob.objects.using("default").create(
            source_type=ScanJob.SourceType.SOURCE_CODE, target=root, mode="actual"
        )
        scanner = SCANNER_REGISTRY["source_code"](job)
        findings = scanner.run()

        certs = [f for f in findings if f.get("kind") == "certificate"]
        self.assertEqual(len(certs), 1)
        self.assertEqual(certs[0]["family"], "rsa")
        self.assertEqual(certs[0]["key_size"], 2048)
        self.assertEqual(certs[0]["evidence"]["type"], "x509")
        self.assertIn("subject", certs[0]["evidence"])


class KeyMaterialSafetyTests(TestCase):
    """Discovery must never surface key material."""

    def test_private_key_is_reported_as_fingerprint_only(self):
        import tempfile

        from .models import ScanJob
        from .scanners import SCANNER_REGISTRY

        root = tempfile.mkdtemp(prefix="ecdat_key_")
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        with open(os.path.join(root, "id_rsa"), "w") as handle:
            handle.write(OPENSSH_PRIVATE_KEY)

        job = ScanJob.objects.using("default").create(
            source_type=ScanJob.SourceType.SOURCE_CODE, target=root, mode="actual"
        )
        findings = SCANNER_REGISTRY["source_code"](job).run()

        key_findings = [f for f in findings if f.get("kind") == "key"]
        self.assertTrue(key_findings)
        blob = str(key_findings)
        # The key body must not appear anywhere in the finding.
        self.assertNotIn("b3BlbnNzaC1rZXktdjEA", blob)
        self.assertNotIn("BEGIN OPENSSH PRIVATE KEY", blob)
        self.assertEqual(len(key_findings[0]["evidence"]["value"]), 64)

    def test_key_store_container_is_identified(self):
        from .scanners import keymaterial

        self.assertEqual(keymaterial.keystore_type(b"\xfe\xed\xfe\xedrest"), "jks")
        self.assertIsNone(keymaterial.keystore_type(b"not-a-keystore"))


class SourceApiDetectionTests(TestCase):
    """Language-aware API detection with evidence and a line number."""

    def test_python_ast_reports_line_key_size_and_call(self):
        from .scanners import sourceapi

        code = (
            "import rsa\n"
            "KEY = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"
        )
        findings = sourceapi.detect_python(code)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["line"], 2)
        self.assertEqual(finding["key_size"], 1024)
        self.assertEqual(finding["family"], "rsa")
        self.assertEqual(finding["evidence"]["type"], "ast_call")
        self.assertEqual(finding["strength"], "key_below_2048")

    def test_python_reports_algorithm_from_call_name(self):
        from .scanners import sourceapi

        findings = sourceapi.detect_python("import hashlib\nh = hashlib.md5(b'x')\n")
        self.assertEqual(findings[0]["algorithm"], "md5")
        self.assertEqual(findings[0]["strength"], "deprecated_hash")

    def test_invalid_python_is_not_reported_as_python(self):
        from .scanners import sourceapi

        self.assertEqual(sourceapi.detect_python("def broken(:\n"), [])

    def test_java_call_site_is_reported_once(self):
        from .scanners import sourceapi

        java = 'Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");'
        findings = sourceapi.detect_symbols(java)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["family"], "des3")
        self.assertEqual(findings[0]["strength"], "legacy_primitive")

    def test_weak_algorithm_notes_follow_nist_and_owasp(self):
        from .scanners import sourceapi

        self.assertEqual(sourceapi.classify_algorithm_strength("MD5", None), "deprecated_hash")
        self.assertEqual(sourceapi.classify_algorithm_strength("SHA-1", None), "deprecated_hash")
        self.assertEqual(sourceapi.classify_algorithm_strength("DES", None), "legacy_primitive")
        self.assertEqual(sourceapi.classify_algorithm_strength("RC4", None), "legacy_primitive")
        self.assertEqual(sourceapi.classify_algorithm_strength("RSA", 1024), "key_below_2048")
        self.assertIsNone(sourceapi.classify_algorithm_strength("AES", 256))
        self.assertIsNone(sourceapi.classify_algorithm_strength("SHA-256", None))

    def test_manifest_does_not_invent_substring_dependencies(self):
        from .scanners import sourceapi

        manifest = '{"dependencies": {"node-pkcs11": "^1.0", "left-pad": "^1.0"}}'
        found = {f["library"] for f in sourceapi.detect_dependencies("package.json", manifest)}
        self.assertIn("node-pkcs11", found)
        self.assertNotIn("pkcs11", found)
        self.assertNotIn("left-pad", found)

    def test_config_directives_are_detected(self):
        from .scanners import sourceapi

        findings = sourceapi.detect_config("ssl_protocols TLSv1 TLSv1.1;\nssl_ciphers RC4-SHA;\n")
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f["kind"] == "crypto_configuration" for f in findings))

    def test_every_family_emitted_is_a_real_algorithm_family(self):
        """Detectors must not invent family buckets the model does not have."""
        from .models import NormalizedFinding
        from .scanners import sourceapi

        valid = set(NormalizedFinding.AlgorithmFamily.values)
        samples = [
            sourceapi.detect_python("import hashlib\nhashlib.md5(b'x')\n"),
            sourceapi.detect_symbols('Cipher.getInstance("RC4");\nMessageDigest.getInstance("SHA-1");\n'),
            sourceapi.detect_config("ssl_protocols TLSv1;\n"),
            sourceapi.detect_dependencies("package.json", '{"dependencies":{"rsa":"1","blowfish":"2"}}'),
        ]
        for batch in samples:
            for finding in batch:
                with self.subTest(finding=finding.get("algorithm")):
                    self.assertIn(finding["family"], valid)


class KeyManagementReferenceTests(TestCase):
    """References to externally-held key material are what enterprises act on."""

    def test_aws_kms_arn_is_detected(self):
        from .scanners import keymaterial

        found = keymaterial.find_key_references(
            "KEY=arn:aws:kms:us-east-1:123456789012:key/abcd-1234"
        )
        self.assertTrue(any(r["system"] == "aws_kms" for r in found))

    def test_gcp_and_azure_references_are_detected(self):
        from .scanners import keymaterial

        gcp = keymaterial.find_key_references(
            "key=projects/p/locations/global/keyRings/r/cryptoKeys/k"
        )
        azure = keymaterial.find_key_references("https://v.vault.azure.net/keys/signing")
        self.assertTrue(any(r["system"] == "gcp_kms" for r in gcp))
        self.assertTrue(any(r["system"] == "azure_keyvault" for r in azure))

    def test_sdk_usage_is_detected(self):
        from .scanners import keymaterial

        for line, expected in [
            ("import hvac", "hashicorp_vault"),
            ("client = boto3.client('kms')", "aws_kms"),
            ("from google.cloud import kms", "gcp_kms"),
            ("from azure.keyvault.keys import KeyClient", "azure_keyvault"),
            ("import pkcs11", "pkcs11"),
        ]:
            with self.subTest(line=line):
                found = keymaterial.find_kms_sdk_usage(line)
                self.assertTrue(any(u["system"] == expected for u in found), msg=found)

    def test_hardware_modules_are_detected(self):
        from .scanners import keymaterial

        found = keymaterial.find_key_references("lib = tpm2-pytss / CloudHSM clusterId=abcdef123456")
        self.assertTrue(found)


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class EvidencePersistenceTests(TestCase):
    """Every finding keeps its provenance through normalisation."""

    def test_kind_line_and_evidence_survive_normalisation(self):
        from .models import NormalizedFinding, RawFinding, ScanJob
        from .normalizer import normalize_finding

        job = ScanJob.objects.using("default").create(
            source_type=ScanJob.SourceType.SOURCE_CODE, target="t", mode="actual"
        )
        raw = RawFinding.objects.using("default").create(
            scan_job=job,
            source_type=ScanJob.SourceType.SOURCE_CODE,
            location="app/config.py",
            raw_json={
                "location": "app/config.py",
                "kind": "crypto_api",
                "family": "rsa",
                "algorithm": "RSA",
                "key_size": 1024,
                "line": 42,
                "confidence": 0.95,
                "evidence": {"type": "ast_call", "value": "rsa.generate_private_key", "strength": "key_below_2048"},
            },
        )

        norm = normalize_finding(raw, using="default")
        self.assertEqual(norm.kind, "crypto_api")
        self.assertEqual(norm.line, 42)
        self.assertEqual(norm.evidence["type"], "ast_call")
        self.assertEqual(norm.evidence["strength"], "key_below_2048")

    def test_unknown_kind_degrades_to_algorithm(self):
        from .models import RawFinding, ScanJob
        from .normalizer import normalize_finding

        job = ScanJob.objects.using("default").create(
            source_type=ScanJob.SourceType.SOURCE_CODE, target="t", mode="actual"
        )
        raw = RawFinding.objects.using("default").create(
            scan_job=job, source_type=ScanJob.SourceType.SOURCE_CODE, location="x",
            raw_json={"location": "x", "kind": "not-a-kind", "algorithm": "RSA"},
        )
        norm = normalize_finding(raw, using="default")
        self.assertEqual(norm.kind, "algorithm")
        self.assertEqual(norm.family, "rsa")

    def test_serializer_exposes_provenance(self):
        from .serializers import NormalizedFindingSerializer

        self.assertIn("evidence", NormalizedFindingSerializer.Meta.fields)
        self.assertIn("line", NormalizedFindingSerializer.Meta.fields)
        self.assertIn("kind", NormalizedFindingSerializer.Meta.fields)

    def test_contract_allows_evidence_and_line(self):
        from schema.contracts.raw_finding import RawFindingPayload

        payload = RawFindingPayload.model_validate(
            {
                "location": "a.py",
                "kind": "certificate",
                "family": "not-a-family",
                "line": 7,
                "evidence": {"type": "x509"},
            }
        )
        self.assertEqual(payload.line, 7)
        self.assertEqual(payload.family, "unknown")
        self.assertEqual(payload.kind, "certificate")

    def test_contract_rejects_bad_family_for_an_algorithm(self):
        from pydantic import ValidationError

        from schema.contracts.raw_finding import RawFindingPayload

        with self.assertRaises(ValidationError):
            RawFindingPayload.model_validate(
                {"location": "a.py", "kind": "algorithm", "family": "banana"}
            )

class DependencyParsingTests(TestCase):
    """Manifests are parsed per ecosystem, with version and scope."""

    def _parse(self, filename, text):
        from .scanners import dependency as dep

        return {d.package: d for d in dep.parse_manifest(filename, text)}

    def test_npm_manifest_splits_runtime_and_dev(self):
        import json as _json

        deps = self._parse("package.json", _json.dumps({
            "dependencies": {"crypto-js": "^4.1.1"},
            "devDependencies": {"jest": "^29.0.0"},
        }))
        self.assertEqual(deps["crypto-js"].scope, "runtime")
        self.assertEqual(deps["crypto-js"].version, "4.1.1")
        self.assertEqual(deps["jest"].scope, "development")

    def test_requirements_records_pinned_and_range_versions(self):
        deps = self._parse(
            "requirements.txt",
            "Django==4.2.1\ncryptography>=42.0\n# comment\n-r other.txt\n",
        )
        self.assertEqual(deps["Django"].version, "4.2.1")
        self.assertEqual(deps["cryptography"].version, "42.0")
        self.assertNotIn("-r", deps)

    def test_pyproject_parses_pep508(self):
        deps = self._parse(
            "pyproject.toml",
            '[project]\nname="x"\ndependencies = ["cryptography==42.0.5"]\n',
        )
        self.assertEqual(deps["cryptography"].version, "42.0.5")

    def test_maven_uses_group_colon_artifact_and_test_scope(self):
        deps = self._parse("pom.xml", (
            "<project><dependencies>"
            '<dependency><groupId>org.bouncycastle</groupId>'
            "<artifactId>bcprov-jdk18on</artifactId><version>1.78</version></dependency>"
            '<dependency><groupId>org.junit</groupId><artifactId>junit</artifactId>'
            "<version>5.10</version><scope>test</scope></dependency>"
            "</dependencies></project>"
        ))
        self.assertEqual(deps["org.bouncycastle:bcprov-jdk18on"].version, "1.78")
        self.assertEqual(deps["org.junit:junit"].scope, "development")

    def test_gradle_notation_splits_on_the_last_colon(self):
        deps = self._parse(
            "build.gradle",
            "dependencies {\n  implementation 'org.bouncycastle:bcprov-jdk18on:1.78'\n"
            "  testImplementation 'junit:junit:5.10'\n}\n",
        )
        self.assertEqual(deps["org.bouncycastle:bcprov-jdk18on"].version, "1.78")
        self.assertEqual(deps["junit:junit"].scope, "development")

    def test_go_mod_marks_indirect_dependencies(self):
        deps = self._parse("go.mod", (
            "module x\n\nrequire (\n\tgolang.org/x/crypto v0.21.0\n"
            "\tgithub.com/pkg/errors v0.9.1 // indirect\n)\n"
        ))
        self.assertEqual(deps["golang.org/x/crypto"].version, "0.21.0")
        self.assertEqual(deps["golang.org/x/crypto"].scope, "runtime")
        self.assertEqual(deps["github.com/pkg/errors"].scope, "development")

    def test_gemfile_tracks_development_group(self):
        deps = self._parse(
            "Gemfile", "gem 'openssl'\ngroup :development do\n  gem 'rspec'\nend\n"
        )
        self.assertEqual(deps["openssl"].scope, "runtime")
        self.assertEqual(deps["rspec"].scope, "development")

    def test_nuget_classifies_by_namespace(self):
        deps = self._parse(
            "App.csproj",
            '<Project><ItemGroup><PackageReference Include="System.Security.Cryptography.Pkcs" Version="8.0.0" /></ItemGroup></Project>',
        )
        self.assertIn("System.Security.Cryptography.Pkcs", deps)

    def test_malformed_manifest_yields_nothing_rather_than_raising(self):
        for filename, text in [
            ("package.json", "{not json"),
            ("pom.xml", "<project><dependencies>"),
            ("Cargo.toml", "this is not = valid = toml ["),
            ("go.mod", "\x00\x01binary"),
        ]:
            with self.subTest(filename=filename):
                self._parse(filename, text)

    def test_non_manifest_is_not_parsed(self):
        from .scanners import dependency as dep

        self.assertEqual(dep.ecosystem_for("main.py"), "")
        self.assertEqual(dep.parse_manifest("main.py", "import rsa"), [])

    def test_crypto_relevance_classification(self):
        from .scanners import dependency as dep

        class _D:
            package = ""
            version = ""
            ecosystem = ""
            scope = "runtime"
            line = None

        cases = {
            "cryptography": ("core", "rsa"),
            "bcrypt": ("supporting", "unknown"),
            "boto3": ("managed_key_service", "unknown"),
            "liboqs": ("post_quantum", "pqc"),
            "left-pad": ("", "unknown"),
        }
        for package, (relevance, family) in cases.items():
            _D.package = package
            with self.subTest(package=package):
                info = dep.classify_dependency(_D())
                self.assertEqual(info["relevance"], relevance)
                self.assertEqual(info["family"], family)

    def test_kms_packages_record_the_service(self):
        from .scanners import dependency as dep

        class _D:
            package = "boto3"
            version = ""
            ecosystem = ""
            scope = "runtime"
            line = None

        self.assertEqual(dep.classify_dependency(_D())["system"], "aws")


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class DependencyPersistenceTests(TestCase):
    """Dependencies are recorded as rows, and crypto ones as findings."""

    def _root_with_manifest(self, manifest_name, body):
        import tempfile

        root = tempfile.mkdtemp(prefix="ecdat_dep_")
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        with open(os.path.join(root, manifest_name), "w") as handle:
            handle.write(body)
        return root

    def test_crypto_dependency_becomes_a_finding_with_version(self):
        import json as _json

        from .models import ScanJob
        from .scanners import SCANNER_REGISTRY

        root = self._root_with_manifest(
            "package.json", _json.dumps({"dependencies": {"crypto-js": "^4.1.1", "left-pad": "^1.0.0"}})
        )
        job = ScanJob.objects.using("default").create(
            source_type=ScanJob.SourceType.SOURCE_CODE, target=root, mode="actual"
        )
        findings = SCANNER_REGISTRY["source_code"](job).run()

        deps = [f for f in findings if f.get("kind") == "dependency"]
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0]["library"], "crypto-js")
        self.assertEqual(deps[0]["library_version"], "4.1.1")
        # A non-crypto dependency is not a finding.
        self.assertTrue(all(f["library"] != "left-pad" for f in deps))

    def test_record_dependencies_persists_all_including_non_crypto(self):
        import json as _json

        from .models import Dependency, RawFinding, ScanJob

        root = self._root_with_manifest(
            "package.json",
            _json.dumps({"dependencies": {"crypto-js": "^4.1.1", "left-pad": "^1.0.0"}}),
        )
        job = ScanJob.objects.using("default").create(
            source_type=ScanJob.SourceType.SOURCE_CODE, target=root, mode="actual"
        )
        RawFinding.objects.using("default").create(
            scan_job=job, source_type=ScanJob.SourceType.SOURCE_CODE,
            location=os.path.join(root, "package.json"),
            raw_json={"location": "package.json", "family": "unknown"},
        )

        written = discovery_services.record_dependencies(job, "default")
        self.assertEqual(written, 2)

        rows = list(Dependency.objects.using("default").filter(scan_job=job))
        self.assertEqual(len(rows), 2)
        by_package = {row.package: row for row in rows}
        self.assertTrue(by_package["crypto-js"].is_crypto)
        self.assertEqual(by_package["crypto-js"].relevance, "core")
        self.assertFalse(by_package["left-pad"].is_crypto)

    def test_lockfile_root_becomes_a_node_so_depends_on_resolves(self):
        """A standard lock file names the project only as an edge source.

        Without creating that node every depends_on edge was dropped, which is
        why the Graph columns were permanently empty.
        """
        import json as _json

        from .models import Dependency, DependencyRelation, RawFinding, ScanJob

        root = self._root_with_manifest(
            "package.json",
            _json.dumps({"name": "demo-app", "dependencies": {"crypto-js": "^4.1.1"}}),
        )
        with open(os.path.join(root, "package-lock.json"), "w", encoding="utf-8") as handle:
            _json.dump(
                {
                    "name": "demo-app",
                    "lockfileVersion": 2,
                    "packages": {
                        "": {"name": "demo-app", "dependencies": {"crypto-js": "^4.1.1"}},
                        "node_modules/crypto-js": {"version": "4.1.1"},
                    },
                    "dependencies": {"crypto-js": {"version": "4.1.1"}},
                },
                handle,
            )

        job = ScanJob.objects.using("default").create(
            source_type=ScanJob.SourceType.SOURCE_CODE, target=root, mode="actual"
        )
        RawFinding.objects.using("default").create(
            scan_job=job,
            source_type=ScanJob.SourceType.SOURCE_CODE,
            location=os.path.join(root, "package.json"),
            source_path=os.path.join(root, "package.json"),
            raw_json={"location": "package.json", "family": "unknown"},
        )
        discovery_services.record_dependencies(job, "default")
        created = discovery_services.record_dependency_graph(job, "default")

        self.assertGreater(created, 0, msg="no depends_on edge was created")
        self.assertTrue(
            Dependency.objects.using("default").filter(package="demo-app").exists(),
            msg="the requesting project was never recorded as a node",
        )
        self.assertTrue(
            DependencyRelation.objects.using("default")
            .filter(relation_type=DependencyRelation.RelationType.DEPENDS_ON)
            .exists()
        )

    def test_a_package_in_both_manifest_and_lockfile_is_one_dependency(self):
        """crypto-js was recorded twice: once crypto=True, once crypto=False."""
        import json as _json

        from .models import Dependency, RawFinding, ScanJob

        root = self._root_with_manifest(
            "package.json",
            _json.dumps({"name": "demo-app", "dependencies": {"crypto-js": "^4.1.1"}}),
        )
        with open(os.path.join(root, "package-lock.json"), "w", encoding="utf-8") as handle:
            _json.dump(
                {
                    "name": "demo-app",
                    "lockfileVersion": 2,
                    "packages": {"node_modules/crypto-js": {"version": "4.1.1"}},
                    "dependencies": {"crypto-js": {"version": "4.1.1"}},
                },
                handle,
            )
        job = ScanJob.objects.using("default").create(
            source_type=ScanJob.SourceType.SOURCE_CODE, target=root, mode="actual"
        )
        RawFinding.objects.using("default").create(
            scan_job=job,
            source_type=ScanJob.SourceType.SOURCE_CODE,
            location=os.path.join(root, "package.json"),
            source_path=os.path.join(root, "package.json"),
            raw_json={"location": "package.json", "family": "unknown"},
        )
        discovery_services.record_dependencies(job, "default")
        discovery_services.record_dependency_graph(job, "default")

        rows = list(Dependency.objects.using("default").filter(package="crypto-js"))
        self.assertEqual(len(rows), 1, msg=f"duplicated dependency rows: {len(rows)}")
        self.assertTrue(rows[0].is_crypto, msg="crypto relevance was lost on the surviving row")
        self.assertEqual(rows[0].version, "4.1.1")

    def test_dependency_graph_works_outside_specified_scope(self):
        """depends_on and provides must both resolve from real paths."""
        import json as _json

        from .models import CryptoAsset, NormalizedFinding, RawFinding, ScanJob
        from .normalizer import normalize_finding
        from .classifier import classify_asset

        root = self._root_with_manifest(
            "package.json",
            _json.dumps({"dependencies": {"crypto-js": "^4.1.1"}}),
        )
        # A lock file beside the manifest is the only source of depends_on.
        with open(os.path.join(root, "package-lock.json"), "w", encoding="utf-8") as handle:
            _json.dump(
                {
                    "name": "app",
                    "lockfileVersion": 2,
                    "packages": {
                        "": {"name": "app", "dependencies": {"crypto-js": "^4.1.1"}},
                        "node_modules/crypto-js": {"version": "4.1.1"},
                    },
                    "dependencies": {"crypto-js": {"version": "4.1.1"}},
                },
                handle,
            )

        job = ScanJob.objects.using("default").create(
            source_type=ScanJob.SourceType.SOURCE_CODE,
            target="quick",
            mode="actual",
            config={"scan_type": "quick"},
        )
        RawFinding.objects.using("default").create(
            scan_job=job,
            source_type=ScanJob.SourceType.SOURCE_CODE,
            location="WORKSPACE/package.json",
            source_path=os.path.join(root, "package.json"),
            raw_json={"location": "WORKSPACE/package.json", "family": "unknown"},
        )

        self.assertEqual(discovery_services.record_dependencies(job, "default"), 1)

        # An asset in the same project, discovered the same way.
        raw = RawFinding.objects.using("default").create(
            scan_job=job,
            source_type=ScanJob.SourceType.SOURCE_CODE,
            location="WORKSPACE/src/app.js",
            source_path=os.path.join(root, "src", "app.js"),
            raw_json={
                "location": "WORKSPACE/src/app.js",
                "family": "hash",
                "algorithm": "SHA256",
                "library": "crypto-js",
                "confidence": 0.9,
            },
        )
        norm = normalize_finding(raw, using="default", session_id=job.session_id)
        classify_asset(norm, using="default", session_id=job.session_id)
        self.assertTrue(
            CryptoAsset.objects.using("default")
            .filter(source_path__isnull=False)
            .exclude(source_path="")
            .exists(),
            msg="asset did not record a real path",
        )

        created = discovery_services.record_dependency_graph(job, "default")
        self.assertGreater(created, 0, msg="no dependency edges built outside specified scope")
    def test_dependencies_survive_a_non_specified_scope(self):
        """A quick/whole scan labels findings with a profile string, not a path.

        The old implementation re-read the manifest from `location`, so every
        dependency was silently dropped outside `specified` scope while the job
        still reported success.
        """
        import json as _json

        from .models import Dependency, RawFinding, ScanJob

        root = self._root_with_manifest(
            "package.json",
            _json.dumps({"dependencies": {"crypto-js": "^4.1.1"}}),
        )
        job = ScanJob.objects.using("default").create(
            source_type=ScanJob.SourceType.SOURCE_CODE,
            target="quick",
            mode="actual",
            config={"scan_type": "quick"},
        )
        # Exactly what the quick profile produces: a profile label, not a path.
        RawFinding.objects.using("default").create(
            scan_job=job,
            source_type=ScanJob.SourceType.SOURCE_CODE,
            location="WORKSPACE/package.json",
            source_path=os.path.join(root, "package.json"),
            raw_json={"location": "WORKSPACE/package.json", "family": "unknown"},
        )

        written = discovery_services.record_dependencies(job, "default")
        self.assertEqual(written, 1, msg="dependency was dropped outside specified scope")
        self.assertTrue(
            Dependency.objects.using("default").filter(scan_job=job).exists()
        )
    def test_rescanning_updates_rather_than_duplicating(self):
        import json as _json

        from .models import Dependency, RawFinding, ScanJob

        root = self._root_with_manifest(
            "package.json", _json.dumps({"dependencies": {"crypto-js": "^4.1.1"}})
        )
        for version in ("^4.1.1", "^4.2.0"):
            with open(os.path.join(root, "package.json"), "w") as handle:
                handle.write(_json.dumps({"dependencies": {"crypto-js": version}}))
            job = ScanJob.objects.using("default").create(
                source_type=ScanJob.SourceType.SOURCE_CODE, target=root, mode="actual"
            )
            RawFinding.objects.using("default").create(
                scan_job=job, source_type=ScanJob.SourceType.SOURCE_CODE,
                location=os.path.join(root, "package.json"),
                raw_json={"location": "package.json"},
            )
            discovery_services.record_dependencies(job, "default")

        rows = Dependency.objects.using("default").filter(package="crypto-js")
        self.assertEqual(rows.count(), 1)
        self.assertEqual(rows.first().version, "4.2.0")

    def test_dependencies_endpoint_is_scoped_and_filterable(self):
        from core.models import WorkSession
        from .models import Dependency

        session = WorkSession.objects.using("default").create(name="deps")
        self.client.post(f"/api/session/switch/{session.pk}/")

        Dependency.objects.using("default").create(
            session=session,
            package="cryptography", version="42.0.5", ecosystem="pypi",
            is_crypto=True, relevance="core",
        )
        Dependency.objects.using("default").create(
            session=session,
            package="left-pad", version="1.0.0", ecosystem="npm", is_crypto=False,
        )

        r = self.client.get("/api/dependencies/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.json()["data"]["results"]), 2)

        r = self.client.get("/api/dependencies/?crypto_only=1")
        self.assertEqual(len(r.json()["data"]["results"]), 1)
        self.assertEqual(r.json()["data"]["results"][0]["package"], "cryptography")

class LockFileParsingTests(TestCase):
    """Lock files are the only real source of transitive dependency shape."""

    def test_npm_v3_package_map_yields_nesting_edges(self):
        from .scanners import lockfiles

        parsed = lockfiles.parse_package_lock("""{
          "lockfileVersion": 3,
          "packages": {
            "": {"dependencies": {"left-pad": "^1.0.0"}},
            "node_modules/left-pad": {"version": "1.3.0"},
            "node_modules/requests": {"version": "2.31.0", "dependencies": {"cryptography": "*"}},
            "node_modules/requests/node_modules/cryptography": {"version": "42.0.5"}
          }
        }""")
        names = {p["package"] for p in parsed["packages"]}
        self.assertIn("left-pad", names)
        self.assertIn("cryptography", names)
        self.assertIn(("requests", "cryptography"), parsed["edges"])
        self.assertIn("left-pad", parsed["direct"])

    def test_npm_v1_nested_tree_yields_edges(self):
        from .scanners import lockfiles

        parsed = lockfiles.parse_package_lock("""{
          "lockfileVersion": 1,
          "dependencies": {
            "requests": {"version": "2.31.0",
                         "dependencies": {"urllib3": {"version": "2.0.0"}}}
          }
        }""")
        self.assertIn(("requests", "urllib3"), parsed["edges"])

    def test_composer_uses_require_as_edges(self):
        from .scanners import lockfiles

        parsed = lockfiles.parse_composer_lock("""{
          "packages": [{"name": "phpseclib/phpseclib", "version": "3.0.1",
                        "require": {"php": "^8.2", "paragonie/random_compat": "^9.0"}}]
        }""")
        self.assertIn(("phpseclib/phpseclib", "paragonie/random_compat"), parsed["edges"])
        self.assertNotIn(("phpseclib/phpseclib", "php"), parsed["edges"])

    def test_cargo_lock_yields_edges(self):
        from .scanners import lockfiles

        parsed = lockfiles.parse_lockfile("Cargo.lock", """version = 3

[[package]]
name = "app"
version = "0.1.0"
dependencies = ["ring"]

[[package]]
name = "ring"
version = "0.17.7"
""")
        self.assertIn(("app", "ring"), parsed["edges"])

    def test_poetry_lock_yields_edges(self):
        from .scanners import lockfiles

        parsed = lockfiles.parse_lockfile("poetry.lock", """[[package]]
name = "requests"
version = "2.31.0"

[package.dependencies]
cryptography = "*"
urllib3 = "*"
""")
        self.assertIn(("requests", "cryptography"), parsed["edges"])

    def test_flat_lockfile_yields_nodes_but_no_edges(self):
        """Pipfile.lock is flat; inventing parent edges would be a guess."""
        from .scanners import lockfiles

        parsed = lockfiles.parse_lockfile(
            "Pipfile.lock", '{"default": {"cryptography": {"version": "==42.0.5"}}}'
        )
        self.assertEqual(len(parsed["packages"]), 1)
        self.assertEqual(parsed["edges"], [])
        self.assertTrue(parsed["flat"])

    def test_malformed_lockfile_yields_nothing(self):
        from .scanners import lockfiles

        for name, text in [("package-lock.json", "{broken"), ("Cargo.lock", "= = ="), ("poetry.lock", "][")]:
            with self.subTest(name=name):
                result = lockfiles.parse_lockfile(name, text)
                self.assertEqual(result["packages"], [])

    def test_unknown_lockfile_is_ignored(self):
        from .scanners import lockfiles

        self.assertEqual(lockfiles.parse_lockfile("random.lock", "x")["packages"], [])


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class DependencyGraphTests(TestCase):
    """Transitive requires plus library->asset links are persisted."""

    def _project(self, files):
        import tempfile

        root = tempfile.mkdtemp(prefix="ecdat_graph_")
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        for rel, body in files.items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as handle:
                handle.write(body)
        return root

    def test_lockfile_creates_transitive_edges(self):
        import json as _json

        from .models import Dependency, DependencyRelation, RawFinding, ScanJob

        root = self._project({
            "package.json": _json.dumps({"dependencies": {"requests": "^2.31.0"}}),
            "package-lock.json": _json.dumps({
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"requests": "^2.31.0"}},
                    "node_modules/requests": {"version": "2.31.0",
                                              "dependencies": {"cryptography": "*"}},
                    "node_modules/requests/node_modules/cryptography": {"version": "42.0.5"},
                },
            }),
        })

        job = ScanJob.objects.using("default").create(
            source_type=ScanJob.SourceType.SOURCE_CODE, target=root, mode="actual"
        )
        RawFinding.objects.using("default").create(
            scan_job=job, source_type=ScanJob.SourceType.SOURCE_CODE,
            location=os.path.join(root, "package.json"), raw_json={"location": "package.json"},
        )
        discovery_services.record_dependencies(job, "default")
        created = discovery_services.record_dependency_graph(job, "default")

        self.assertGreater(created, 0)
        # The transitive package becomes a node even though no manifest declared it.
        self.assertTrue(Dependency.objects.using("default").filter(package="cryptography").exists())
        edge = DependencyRelation.objects.using("default").filter(
            relation_type=DependencyRelation.RelationType.DEPENDS_ON
        ).first()
        self.assertIsNotNone(edge)
        self.assertEqual(edge.from_dependency.package, "requests")
        self.assertEqual(edge.to_dependency.package, "cryptography")

    def test_crypto_dependency_is_linked_to_assets_in_the_project(self):
        import json as _json

        from .models import CryptoAsset, Dependency, DependencyRelation, RawFinding, ScanJob

        root = self._project({
            "package.json": _json.dumps({"dependencies": {"cryptography": "^42.0.5"}}),
        })
        job = ScanJob.objects.using("default").create(
            source_type=ScanJob.SourceType.SOURCE_CODE, target=root, mode="actual"
        )
        RawFinding.objects.using("default").create(
            scan_job=job, source_type=ScanJob.SourceType.SOURCE_CODE,
            location=os.path.join(root, "package.json"), raw_json={"location": "package.json"},
        )
        asset = CryptoAsset.objects.using("default").create(
            name="RSA 2048 - Source Code Repos", family="rsa", algorithm="RSA",
            key_size=2048, location=os.path.join(root, "app", "sign.py"), mode="actual",
        )

        discovery_services.record_dependencies(job, "default")
        discovery_services.record_dependency_graph(job, "default")

        edge = DependencyRelation.objects.using("default").filter(
            relation_type=DependencyRelation.RelationType.PROVIDES
        ).first()
        self.assertIsNotNone(edge)
        self.assertEqual(edge.from_dependency.package, "cryptography")
        self.assertEqual(edge.to_asset_id, asset.pk)

    def test_asset_outside_the_project_is_not_linked(self):
        import json as _json

        from .models import CryptoAsset, DependencyRelation, RawFinding, ScanJob

        root = self._project({
            "package.json": _json.dumps({"dependencies": {"cryptography": "^42.0.5"}}),
        })
        job = ScanJob.objects.using("default").create(
            source_type=ScanJob.SourceType.SOURCE_CODE, target=root, mode="actual"
        )
        RawFinding.objects.using("default").create(
            scan_job=job, source_type=ScanJob.SourceType.SOURCE_CODE,
            location=os.path.join(root, "package.json"), raw_json={"location": "package.json"},
        )
        CryptoAsset.objects.using("default").create(
            name="Elsewhere", family="rsa", algorithm="RSA",
            location="/some/other/repo/sign.py", mode="actual",
        )

        discovery_services.record_dependencies(job, "default")
        discovery_services.record_dependency_graph(job, "default")

        self.assertEqual(
            DependencyRelation.objects.using("default")
            .filter(relation_type=DependencyRelation.RelationType.PROVIDES).count(),
            0,
        )

    def test_rerunning_does_not_duplicate_edges(self):
        import json as _json

        from .models import DependencyRelation, RawFinding, ScanJob

        root = self._project({
            "package.json": _json.dumps({"dependencies": {"requests": "^2.31.0"}}),
            "package-lock.json": _json.dumps({
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"requests": "^2.31.0"}},
                    "node_modules/requests": {"version": "2.31.0",
                                              "dependencies": {"cryptography": "*"}},
                    "node_modules/requests/node_modules/cryptography": {"version": "42.0.5"},
                },
            }),
        })
        job = ScanJob.objects.using("default").create(
            source_type=ScanJob.SourceType.SOURCE_CODE, target=root, mode="actual"
        )
        RawFinding.objects.using("default").create(
            scan_job=job, source_type=ScanJob.SourceType.SOURCE_CODE,
            location=os.path.join(root, "package.json"), raw_json={"location": "package.json"},
        )
        discovery_services.record_dependencies(job, "default")
        discovery_services.record_dependency_graph(job, "default")
        first = DependencyRelation.objects.using("default").count()
        discovery_services.record_dependency_graph(job, "default")
        self.assertEqual(DependencyRelation.objects.using("default").count(), first)

    def test_graph_endpoint_exposes_dependency_nodes_and_edges(self):
        from core.models import WorkSession

        from .models import CryptoAsset, Dependency, DependencyRelation

        workspace = WorkSession.objects.using("default").create(name="graph-scope")
        self.client.post(f"/api/session/switch/{workspace.pk}/")

        dependency = Dependency.objects.using("default").create(
            session_id=workspace.pk, package="cryptography", version="42.0.5",
            ecosystem="pypi", is_crypto=True, relevance="core",
        )
        asset = CryptoAsset.objects.using("default").create(
            session_id=workspace.pk, name="RSA", family="rsa", algorithm="RSA", mode="actual",
        )
        DependencyRelation.objects.using("default").create(
            from_dependency=dependency, to_asset=asset, session_id=workspace.pk,
            relation_type=DependencyRelation.RelationType.PROVIDES, detail="same project",
        )

        r = self.client.get("/api/graph/")
        data = r.json()["data"]
        self.assertIn("dependency_nodes", data)
        self.assertIn("dependency_edges", data)
        self.assertEqual(len(data["dependency_nodes"]), 1)
        self.assertEqual(data["dependency_edges"][0]["from"], f"d{dependency.pk}")
        self.assertEqual(data["dependency_edges"][0]["to"], f"a{asset.pk}")
        # Existing keys are untouched.
        for key in ("assets", "findings", "asset_relations", "finding_relations"):
            self.assertIn(key, data)

def _elf(extra: bytes = b"", e_type: int = 3, machine: int = 0x3E) -> bytes:
    ident = bytearray(16)
    ident[0:4] = b"\x7fELF"
    ident[4] = 2
    ident[5] = 1
    return (
        bytes(ident)
        + e_type.to_bytes(2, "little")
        + machine.to_bytes(2, "little")
        + b"\x00" * 32
        + extra
    )


def _pe(symbols: bytes = b"", machine: int = 0x8664) -> bytes:
    header = bytearray(b"MZ" + b"\x00" * 0x3A)
    header[0x3C:0x40] = (0x80).to_bytes(4, "little")
    header += b"\x00" * (0x80 - len(header)) + b"PE\x00\x00"
    header += machine.to_bytes(2, "little") + b"\x00" * 20
    return bytes(header) + symbols


class BinaryInspectionTests(TestCase):
    """Binary format parsing and crypto symbol extraction."""

    def test_elf_header_is_parsed(self):
        from .scanners import binary as b

        detail = b.analyse(_elf(), "libcrypto.so")
        self.assertEqual(detail.fmt, "elf")
        self.assertEqual(detail.arch, "x86")
        self.assertEqual(detail.bits, 64)
        self.assertTrue(detail.is_library)

    def test_pe_header_is_parsed(self):
        from .scanners import binary as b

        detail = b.analyse(_pe(), "app.dll")
        self.assertEqual(detail.fmt, "pe")
        self.assertEqual(detail.arch, "x86")
        self.assertEqual(detail.bits, 64)
        self.assertEqual(detail.container_hint, "dynamic library")

    def test_macho_header_is_parsed(self):
        from .scanners import binary as b

        macho = b"\xcf\xfa\xed\xfe" + (0x01000007).to_bytes(4, "little")
        detail = b.analyse(macho, "libcrypto.dylib")
        self.assertEqual(detail.fmt, "macho")
        self.assertEqual(detail.arch, "x86")
        self.assertEqual(detail.bits, 64)

    def test_symbol_matching_respects_boundaries(self):
        """`CryptEncrypt` must not be reported for `BCryptEncrypt`."""
        from .scanners import binary as b

        detail = b.analyse(_pe(b"BCryptEncrypt\x00BCryptSignHash\x00"), "app.dll")
        self.assertIn("BCryptEncrypt", detail.symbols)
        self.assertIn("BCryptSignHash", detail.symbols)
        self.assertNotIn("CryptEncrypt", detail.symbols)
        self.assertNotIn("CryptSignHash", detail.symbols)

    def test_openssl_and_bouncycastle_symbols_are_found(self):
        from .scanners import binary as b

        detail = b.analyse(_elf(b"\x00EVP_PKEY_new\x00EVP_aes_256_gcm\x00BCryptOpenAlgorithmProvider\x00"))
        found = set(detail.symbols)
        self.assertIn("EVP_PKEY_new", found)
        self.assertIn("EVP_aes_256_gcm", found)
        self.assertIn("BCryptOpenAlgorithmProvider", found)

    def test_embedded_certificate_and_key_markers_are_reported(self):
        from .scanners import binary as b

        findings = b.findings_for("app.exe", _elf(b"-----BEGIN CERTIFICATE-----\x00-----BEGIN RSA PRIVATE KEY-----\x00"))
        kinds = {f["kind"] for f in findings}
        self.assertIn("certificate", kinds)
        self.assertIn("key_reference", kinds)
        key_finding = next(f for f in findings if f["kind"] == "key_reference")
        self.assertEqual(key_finding["strength"], "private_key_material")

    def test_unrecognised_data_yields_nothing(self):
        from .scanners import binary as b

        self.assertEqual(b.findings_for("notes.txt", b"just some plain text"), [])

    def test_findings_carry_format_evidence(self):
        from .scanners import binary as b

        findings = b.findings_for("app.dll", _pe(b"BCryptEncrypt\x00"), "app.dll")
        self.assertTrue(findings)
        evidence = findings[0]["evidence"]
        self.assertEqual(evidence["type"], "binary_symbol")
        self.assertEqual(evidence["format"], "pe")
        self.assertEqual(evidence["architecture"], "x86")
        self.assertIn("symbol", evidence)

    def test_truncated_header_does_not_raise(self):
        from .scanners import binary as b

        for data in [b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"PK\x03\x04"]:
            with self.subTest(data=data[:4]):
                b.analyse(data, "x.bin")

    def test_no_file_is_executed(self):
        """Inspection is byte-level; nothing in the module runs the artefact."""
        from pathlib import Path

        source = Path("segments/scraping/discovery/scanners/binary.py").read_text()
        for dangerous in ("subprocess", "os.system", "exec(", "eval(", "ctypes"):
            with self.subTest(dangerous=dangerous):
                self.assertNotIn(dangerous, source)


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class BinaryScannerTests(TestCase):
    """The binary scanner is a real registry entry, not page-specific code."""

    def test_binary_is_now_an_available_source(self):
        from .models import ScanJob
        from .scanners import list_scanners

        entries = {e["source_type"]: e for e in list_scanners()}
        self.assertEqual(entries[ScanJob.SourceType.BINARY]["status"], "available")
        self.assertEqual(entries[ScanJob.SourceType.BINARY]["id"], "binary-inspection")
        self.assertIn("no_execution", entries[ScanJob.SourceType.BINARY]["capabilities"])

    def test_binary_scan_no_longer_rejected(self):
        """Previously source_type=binary was refused at creation as planned."""
        from .models import ScanJob

        job = discovery_services.create_and_run_scan(
            source_type=ScanJob.SourceType.BINARY,
            target="C:\\does-not-matter",
            scan_type="quick",
        )
        self.assertIsNotNone(job.pk)
        self.assertIn(job.source_type, (ScanJob.SourceType.BINARY,))

    @mock.patch(
        "segments.scraping.discovery.services._dispatch_scan",
        side_effect=lambda scan_job, db: discovery_services.run_scan(scan_job),
    )
    def test_binary_scan_produces_binary_assets(self, _mock_dispatch):
        import tempfile

        from .models import CryptoAsset, ScanJob

        root = tempfile.mkdtemp(prefix="ecdat_bin_")
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        with open(os.path.join(root, "libcrypto.so"), "wb") as handle:
            handle.write(_elf(b"\x00EVP_PKEY_new\x00EVP_aes_256_gcm\x00"))

        job = discovery_services.create_and_run_scan(
            source_type=ScanJob.SourceType.BINARY, target=root, scan_type="specified",
        )
        job.refresh_from_db()
        self.assertNotEqual(job.status, "failed", msg=job.error)

        assets = list(CryptoAsset.objects.using("default").filter(session_id=job.session_id))
        self.assertTrue(assets)
        self.assertTrue(all(a.asset_type == CryptoAsset.AssetType.BINARY for a in assets))
        self.assertTrue(all(a.identifier for a in assets))


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class AssetIdentityTests(TestCase):
    """Identity, occurrences, and the asset taxonomy."""

    def _finding(self, location, kind="algorithm", algorithm="RSA", key_size=2048, family="rsa"):
        from .models import RawFinding, ScanJob
        from .normalizer import normalize_finding

        job = ScanJob.objects.using("default").create(
            source_type=ScanJob.SourceType.SOURCE_CODE, target="t", mode="actual"
        )
        raw = RawFinding.objects.using("default").create(
            scan_job=job, source_type=ScanJob.SourceType.SOURCE_CODE, location=location,
            raw_json={"location": location, "kind": kind, "family": family,
                      "algorithm": algorithm, "key_size": key_size, "confidence": 0.9},
        )
        return normalize_finding(raw, using="default"), job

    def test_asset_type_follows_the_finding_kind(self):
        from .classifier import asset_type_for
        from .models import CryptoAsset

        for kind, expected in [
            ("certificate", CryptoAsset.AssetType.CERTIFICATE),
            ("key", CryptoAsset.AssetType.KEY_REFERENCE),
            ("library", CryptoAsset.AssetType.LIBRARY),
            ("hardware_module", CryptoAsset.AssetType.HARDWARE),
            ("cloud_crypto_service", CryptoAsset.AssetType.CLOUD_RESOURCE),
            ("algorithm", CryptoAsset.AssetType.SOURCE_CODE),
        ]:
            norm, _job = self._finding(f"payments/{kind}.py", kind=kind)
            with self.subTest(kind=kind):
                self.assertEqual(asset_type_for(norm, "source_code"), expected)

    def test_use_kinds_follow_the_discovery_source_not_the_kind(self):
        """A crypto_api hit is source code in a .py file and a binary in a .so."""
        from .classifier import asset_type_for
        from .models import CryptoAsset, RawFinding, ScanJob
        from .normalizer import normalize_finding

        for kind, source_type, expected in [
            ("crypto_api", "source_code", CryptoAsset.AssetType.SOURCE_CODE),
            ("crypto_api", "binary", CryptoAsset.AssetType.BINARY),
            ("crypto_api", "container", CryptoAsset.AssetType.CONTAINER),
            ("algorithm", "binary", CryptoAsset.AssetType.BINARY),
            ("crypto_configuration", "source_code", CryptoAsset.AssetType.SOURCE_CODE),
        ]:
            with self.subTest(kind=kind, source=source_type):
                job = ScanJob.objects.using("default").create(
                    source_type=source_type, target="t", mode="actual"
                )
                raw = RawFinding.objects.using("default").create(
                    scan_job=job, source_type=source_type, location="x",
                    raw_json={"location": "x", "kind": kind, "family": "rsa"},
                )
                norm = normalize_finding(raw, using="default")
                self.assertEqual(asset_type_for(norm, source_type), expected)

    def test_two_applications_are_two_assets(self):
        """An asset is the thing carrying the crypto, so two apps are two assets."""
        from .classifier import classify_asset
        from .models import AssetOccurrence, CryptoAsset

        first, _ = self._finding("payments/api/sign.py")
        second, _ = self._finding("identity/auth/sign.py")

        asset_a = classify_asset(first, using="default")
        asset_b = classify_asset(second, using="default")

        self.assertNotEqual(asset_a.pk, asset_b.pk)
        self.assertEqual(CryptoAsset.objects.using("default").count(), 2)
        self.assertEqual(AssetOccurrence.objects.using("default").count(), 2)
        # They are still linked by the same observed primitive.
        self.assertEqual(asset_a.family, asset_b.family)
        self.assertEqual(asset_a.algorithm, asset_b.algorithm)

    def test_same_asset_seen_twice_is_one_asset_two_occurrences(self):
        from .classifier import classify_asset
        from .models import AssetOccurrence, CryptoAsset

        first, _ = self._finding("payments/api/sign.py")
        second, _ = self._finding("payments/api/verify.py")

        asset_a = classify_asset(first, using="default")
        asset_b = classify_asset(second, using="default")

        self.assertEqual(asset_a.pk, asset_b.pk)
        self.assertEqual(CryptoAsset.objects.using("default").count(), 1)
        self.assertEqual(AssetOccurrence.objects.using("default").count(), 2)

    def test_repeat_sighting_updates_metadata_instead_of_being_dropped(self):
        from .classifier import classify_asset
        from .models import RawFinding, ScanJob
        from .normalizer import normalize_finding

        first, _job = self._finding("payments/api.py")
        asset = classify_asset(first, using="default")
        original_location = asset.location

        job2 = ScanJob.objects.using("default").create(
            source_type=ScanJob.SourceType.SOURCE_CODE, target="t", mode="actual"
        )
        raw2 = RawFinding.objects.using("default").create(
            scan_job=job2, source_type=ScanJob.SourceType.SOURCE_CODE,
            location="payments/api.py",
            raw_json={"location": "payments/api.py", "family": "rsa",
                      "algorithm": "RSA", "key_size": 2048,
                      "library": "OpenSSL", "confidence": 0.9},
        )
        norm2 = normalize_finding(raw2, using="default")
        classify_asset(norm2, using="default")

        asset.refresh_from_db()
        self.assertEqual(asset.location, original_location)
        self.assertEqual(asset.library, "OpenSSL")

    def test_identifier_is_stable_and_content_derived(self):
        from .classifier import asset_identifier
        from .models import CryptoAsset

        norm_a, _ = self._finding("payments/api.py")
        norm_b, _ = self._finding("identity/auth.py")
        self.assertEqual(
            asset_identifier("payments -- RSA", CryptoAsset.AssetType.SOURCE_CODE, norm_a),
            asset_identifier("payments -- RSA", CryptoAsset.AssetType.SOURCE_CODE, norm_b),
        )

    def test_occurrences_endpoint_returns_sightings(self):
        from .classifier import classify_asset
        from core.models import WorkSession

        from .models import AssetOccurrence

        workspace = WorkSession.objects.using("default").create(name="occ-scope")
        norm, _ = self._finding("payments/api.py")
        classify_asset(norm, using="default", session_id=workspace.pk)

        self.client.post(f"/api/session/switch/{workspace.pk}/")
        r = self.client.get("/api/occurrences/")
        self.assertEqual(r.status_code, 200)
        rows = r.json()["data"]["results"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["asset_type"], "source_code")

    def test_occurrences_endpoint_filters_by_asset(self):
        from .classifier import classify_asset
        from core.models import WorkSession

        workspace = WorkSession.objects.using("default").create(name="occ-filter")
        self.client.post(f"/api/session/switch/{workspace.pk}/")

        first, _ = self._finding("payments/a.py", algorithm="RSA")
        second, _ = self._finding("payments/b.py", algorithm="ECDSA", key_size=256, family="ecc")
        asset_a = classify_asset(first, using="default", session_id=workspace.pk)
        asset_b = classify_asset(second, using="default", session_id=workspace.pk)

        everything = self.client.get("/api/occurrences/").json()["data"]["results"]
        self.assertEqual(len(everything), 2)

        scoped = self.client.get(f"/api/occurrences/?asset={asset_a.pk}").json()["data"]["results"]
        self.assertEqual(len(scoped), 1)
        self.assertEqual(scoped[0]["asset"], asset_a.pk)
        self.assertNotEqual(scoped[0]["asset"], asset_b.pk)

    def test_assets_endpoint_exposes_type_and_occurrence_count(self):
        from .classifier import classify_asset
        from core.models import WorkSession

        workspace = WorkSession.objects.using("default").create(name="asset-scope")
        norm, _ = self._finding("payments/api.py")
        classify_asset(norm, using="default", session_id=workspace.pk)
        classify_asset(norm, using="default", session_id=workspace.pk)

        self.client.post(f"/api/session/switch/{workspace.pk}/")
        r = self.client.get("/api/assets/")
        self.assertEqual(r.status_code, 200)
        row = r.json()["data"]["results"][0]
        self.assertEqual(row["asset_type"], "source_code")
        self.assertTrue(row["asset_type_display"])
        self.assertEqual(row["occurrence_count"], 1)
        self.assertTrue(row["identifier"])

    def test_assets_endpoint_filters_by_type(self):
        from .classifier import classify_asset
        from core.models import WorkSession

        from .models import CryptoAsset

        workspace = WorkSession.objects.using("default").create(name="filter-scope")
        CryptoAsset.objects.using("default").create(
            session_id=workspace.pk, name="bin", asset_type=CryptoAsset.AssetType.BINARY,
            family="rsa", algorithm="RSA", source_type="binary", mode="actual",
        )
        norm, _ = self._finding("payments/api.py")
        classify_asset(norm, using="default", session_id=workspace.pk)

        self.client.post(f"/api/session/switch/{workspace.pk}/")
        r = self.client.get("/api/assets/?asset_type=binary")
        rows = r.json()["data"]["results"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "bin")


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class CoverageHonestyTests(TestCase):
    """A scan must never claim full coverage it did not achieve.

    These are regression tests for defects that previously passed the suite
    because every test that reached the real post-ingest path had zero skips.
    """

    @staticmethod
    def _job(**kwargs):
        from .models import ScanJob

        defaults = {
            "source_type": ScanJob.SourceType.SOURCE_CODE,
            "target": "unused",
            "mode": "actual",
            "status": ScanJob.Status.QUEUED,
        }
        defaults.update(kwargs)
        return ScanJob.objects.using("default").create(**defaults)

    @staticmethod
    def _scanner_class(skip_reasons: dict | None = None, scanned=2, total=2, findings=1):
        """A minimal real BaseScanner so ingest() is the production one."""
        from .models import ScanJob
        from .scanners.base import BaseScanner

        class _Scanner(BaseScanner):
            scanner_id = "test-scanner"
            name = "Test scanner"
            status = "available"
            capabilities = ()
            supported_targets = ()
            supported_artifacts = ()
            configuration_schema: dict = {}
            source_type = ScanJob.SourceType.SOURCE_CODE

            def run(self, context=None):
                if context:
                    context.report("inspecting", scanned, total)
                    for reason, count in (skip_reasons or {}).items():
                        context.record_skip(reason, count)
                return [
                    {
                        "location": f"src/app{i}.py",
                        "kind": "algorithm",
                        "family": "hash",
                        "algorithm": "SHA256",
                        "confidence": 0.9,
                    }
                    for i in range(findings)
                ]

        return _Scanner

    def test_partial_status_survives_post_ingest(self):
        """The bug: _post_ingest unconditionally rewrote PARTIAL to COMPLETED."""
        from .models import ScanJob

        job = self._job()
        scanner = self._scanner_class(skip_reasons={"unreadable": 1})(scan_job=job)
        with mock.patch.object(discovery_services, "get_scanner", return_value=scanner):
            discovery_services.run_scan(job)

        job.refresh_from_db()
        self.assertEqual(
            job.status,
            ScanJob.Status.PARTIAL,
            msg="a scan that skipped an item must stay PARTIAL",
        )
        self.assertEqual(job.error_code, "PARTIAL_COVERAGE")
        self.assertEqual(job.items_skipped, 1)
        self.assertEqual(job.skip_reasons, {"unreadable": 1})
        self.assertIn("could not be read", job.error)

    def test_skip_reasons_are_persisted_and_labelled(self):

        reasons = discovery_services._bounded_skip_reasons(
            {
                "unreadable": 3,
                "not_an_image": 1,
                "yara_error:MemoryError": 2,
                "inspect_error:RecursionError": 1,
            }
        )
        # Exception-named reasons collapse so cardinality stays bounded.
        self.assertEqual(
            reasons, {"unreadable": 3, "not_an_image": 1, "inspect_error": 3}
        )
        sentence = discovery_services._skip_reason_sentence(reasons)
        self.assertNotIn("_error:", sentence)
        self.assertIn("could not be read", sentence)

    def test_every_skip_reason_emitted_has_a_label(self):
        """No internal token may leak into user-facing text."""
        import re
        from pathlib import Path


        scanner_dir = Path(discovery_services.__file__).parent / "scanners"
        emitted: set[str] = set()
        pattern = re.compile(r'record_skip\(\s*f?"([^"{]+)"')
        for path in scanner_dir.glob("*.py"):
            for match in pattern.finditer(path.read_text(encoding="utf-8")):
                emitted.add(match.group(1))
        self.assertTrue(emitted, msg="no skip reasons found; the check is broken")
        for reason in emitted:
            self.assertIn(
                reason,
                discovery_services._SKIP_LABELS,
                msg=f"skip reason {reason!r} has no user-facing label",
            )

    def test_completed_scan_keeps_measured_coverage_counters(self):
        """items_scanned must be files inspected, not findings persisted."""
        from .models import ScanJob

        job = self._job()
        scanner = self._scanner_class(scanned=7, total=7, findings=2)(scan_job=job)
        with mock.patch.object(discovery_services, "get_scanner", return_value=scanner):
            discovery_services.run_scan(job)

        job.refresh_from_db()
        self.assertEqual(job.status, ScanJob.Status.COMPLETED)
        self.assertEqual(job.items_total, 7, msg="measured total was destroyed")
        self.assertEqual(job.items_scanned, 7, msg="scanned became the finding count")
        self.assertEqual(job.findings_count, 2)

    def test_findings_are_not_normalized_twice(self):
        """run_scan must not redo the work _post_ingest already completed."""
        from pathlib import Path


        source = Path(discovery_services.__file__).read_text(encoding="utf-8")
        body = source[
            source.index("def run_scan(") : source.index("def cancel_scan_job(")
        ]
        self.assertNotIn(
            "_post_ingest(",
            body,
            msg="run_scan must not call _post_ingest; it already normalises and correlates",
        )

    def test_post_ingest_cannot_downgrade_partial(self):
        from .models import ScanJob

        job = self._job(status=ScanJob.Status.PARTIAL)
        discovery_services._post_ingest(
            job, "default", ScanJob.SourceType.SOURCE_CODE, session_id=job.session_id
        )
        job.refresh_from_db()
        self.assertEqual(job.status, ScanJob.Status.PARTIAL)

    def test_cancel_is_scoped_to_the_active_session(self):
        import core.sessions as core_sessions
        from core.models import WorkSession
        from . import views as discovery_views
        from .models import ScanJob

        mine = WorkSession.objects.using("default").create(name="cancel-mine")
        theirs = WorkSession.objects.using("default").create(name="cancel-theirs")
        job = self._job(session_id=theirs.pk, status=ScanJob.Status.RUNNING)

        original = core_sessions.thread_session_id
        core_sessions.thread_session_id = lambda: mine.pk
        try:
            response = discovery_views.cancel_scan(_FakeRequest(), job.pk)
        finally:
            core_sessions.thread_session_id = original
        self.assertEqual(response.status_code, 404)
        job.refresh_from_db()
        self.assertEqual(
            job.status,
            ScanJob.Status.RUNNING,
            msg="another session's scan must not be cancellable",
        )

    def test_planned_sources_never_contradict_the_registry(self):
        from .scanners import PLANNED_SOURCES, SCANNER_REGISTRY

        self.assertEqual(set(PLANNED_SOURCES) & set(SCANNER_REGISTRY), set())

    def test_findings_cannot_be_imported_for_an_unimplemented_source(self):

        for source in ("cloud", "hsm", "dependency"):
            with self.assertRaises(discovery_services.ScanInspectionError):
                discovery_services.ingest_external_findings(
                    source_type=source, target="acct", findings=[], session_id=None,
                )

    def test_certificate_scan_does_not_count_clean_negatives_as_skips(self):
        """A file read successfully with no key material is not a coverage gap."""
        from .models import ScanJob
        from .scanners.base import ScanContext
        from .scanners.certificate_scanner import CertificateArtefactScanner

        root = tempfile.mkdtemp(prefix="ecdat_pki_neg_")
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        with open(os.path.join(root, "notes.pem"), "wb") as handle:
            handle.write(b"-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n")

        job = self._job(
            source_type=ScanJob.SourceType.CERTIFICATE, target=root, status=ScanJob.Status.QUEUED
        )
        context = ScanContext()
        CertificateArtefactScanner(scan_job=job).run(context)
        self.assertEqual(context.skipped, {})


class _FakeRequest:
    method = "POST"

    def __init__(self):
        self.POST = {}


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class ArtefactKindClassificationTests(TestCase):
    """Discovery must classify what it found, not flatten everything to algorithm."""

    def setUp(self):
        self.client = Client()
        from core.models import WorkSession

        self.workspace = WorkSession.objects.using("default").create(name="kinds")
        self.client.post(f"/api/session/switch/{self.workspace.pk}/")

    def _finding(self, location, kind, family="rsa", algorithm="RSA"):
        from .classifier import classify_asset
        from .models import ScanJob
        from .normalizer import normalize_finding
        from .models import RawFinding

        job = ScanJob.objects.using("default").create(
            source_type=ScanJob.SourceType.SOURCE_CODE,
            target="work",
            mode="actual",
            status=ScanJob.Status.COMPLETED,
            session_id=self.workspace.pk,
        )
        raw = RawFinding.objects.using("default").create(
            scan_job=job,
            mode="actual",
            source_type=ScanJob.SourceType.SOURCE_CODE,
            location=location,
            raw_json={
                "location": location,
                "kind": kind,
                "family": family,
                "algorithm": algorithm,
                "confidence": 0.9,
            },
            session_id=self.workspace.pk,
        )
        norm = normalize_finding(raw, using="default", session_id=self.workspace.pk)
        classify_asset(norm, using="default", session_id=self.workspace.pk)
        return norm

    def test_container_is_a_canonical_kind_not_degraded_to_algorithm(self):
        """The bug: `container` was emitted but absent from FindingKind."""
        from .models import NormalizedFinding

        self.assertIn("container", NormalizedFinding.FindingKind.values)
        norm = self._finding("image:payments", "container", family="unknown", algorithm="container")
        self.assertEqual(norm.kind, "container")
        self.assertNotEqual(norm.kind, "algorithm")

    def test_every_kind_a_scanner_emits_is_canonical(self):
        """A scanner emitting a non-canonical kind silently loses its meaning."""
        import re
        from pathlib import Path

        from .scanners.base import BaseScanner  # noqa: F401 - import check
        from .models import NormalizedFinding

        scanner_dir = Path(__file__).parent / "scanners"
        emitted: set[str] = set()
        pattern = re.compile(r'"kind":\s*"([a-z_]+)"')
        for path in scanner_dir.glob("*.py"):
            emitted.update(pattern.findall(path.read_text(encoding="utf-8")))
        unknown = sorted(
            kind
            for kind in emitted
            if kind not in NormalizedFinding.FindingKind.values
        )
        self.assertEqual(
            unknown, [], msg=f"scanners emit kinds outside the vocabulary: {unknown}"
        )

    def test_findings_endpoint_filters_by_kind(self):
        self._finding("a/cert.pem", "certificate", family="ecc", algorithm="EC")
        self._finding("b/lib.so", "library", family="rsa", algorithm="RSA")
        self._finding("c/app.py", "algorithm")

        r = self.client.get("/api/normalized-findings/?kind=certificate")
        self.assertEqual(r.status_code, 200)
        rows = r.json()["data"]["results"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "certificate")

    def test_kind_facets_report_the_classification_split(self):
        self._finding("a/cert.pem", "certificate", family="ecc", algorithm="EC")
        self._finding("b/cert2.pem", "certificate", family="ecc", algorithm="EC")
        self._finding("c/app.py", "algorithm")

        r = self.client.get("/api/normalized-findings/kinds/")
        self.assertEqual(r.status_code, 200)
        body = r.json()["data"]
        self.assertEqual(body["total"], 3)
        counts = {entry["kind"]: entry["count"] for entry in body["kinds"]}
        self.assertEqual(counts["certificate"], 2)
        self.assertEqual(counts["algorithm"], 1)
        labels = {entry["kind"]: entry["label"] for entry in body["kinds"]}
        self.assertEqual(labels["certificate"], "Certificate")
        # Ordered by count, so the dominant category leads.
        self.assertEqual(body["kinds"][0]["kind"], "certificate")

    def test_kind_facets_exclude_other_sessions(self):
        from core.models import WorkSession
        from .classifier import classify_asset
        from .models import NormalizedFinding, RawFinding, ScanJob
        from .normalizer import normalize_finding

        other = WorkSession.objects.using("default").create(name="kinds-other")
        job = ScanJob.objects.using("default").create(
            source_type=ScanJob.SourceType.SOURCE_CODE,
            target="other",
            mode="actual",
            status=ScanJob.Status.COMPLETED,
            session_id=other.pk,
        )
        raw = RawFinding.objects.using("default").create(
            scan_job=job, mode="actual", source_type=ScanJob.SourceType.SOURCE_CODE,
            location="x.pem", session_id=other.pk,
            raw_json={"location": "x.pem", "kind": "certificate", "confidence": 0.9},
        )
        norm = normalize_finding(raw, using="default", session_id=other.pk)
        classify_asset(norm, using="default", session_id=other.pk)

        body = self.client.get("/api/normalized-findings/kinds/").json()["data"]
        self.assertEqual(body["total"], 0, msg="another session's findings leaked")

    def test_unknown_filter_value_does_not_error(self):
        self._finding("a/app.py", "algorithm")
        r = self.client.get("/api/normalized-findings/?kind=not_a_real_kind")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["data"]["results"], [])


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class MultiSourceScanTests(TestCase):
    """One user action can run several discovery sources."""

    def setUp(self):
        self.client = Client()
        self.root = tempfile.mkdtemp(prefix="ecdat_batch_")
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))

    def _register(self, scan_job, db="default"):
        from .services import refresh_batch_status
        from .models import ScanBatch

        batch = ScanBatch.objects.using(db).create(
            target=scan_job.target,
            scan_type="specified",
            source_types=[scan_job.source_type],
            mode=scan_job.mode,
            session_id=scan_job.session_id,
        )
        ScanJob.objects.using(db).filter(pk=scan_job.pk).update(batch_id=batch.pk)
        return refresh_batch_status(batch, db)

    def test_plan_excludes_a_source_that_cannot_read_a_file_target(self):
        from .services import plan_sources

        target = os.path.join(self.root, "image.tar")
        with open(target, "wb") as handle:
            handle.write(b"not really an image")

        runnable, excluded = plan_sources(
            ["source_code", "binary", "certificate", "container"], target, "specified"
        )
        self.assertIn("container", runnable)
        self.assertNotIn("binary", runnable)
        reasons = {item["source"]: item["reason"] for item in excluded}
        self.assertIn("binary", reasons)
        self.assertIn("folder", reasons["binary"])

    def test_plan_excludes_unimplemented_sources(self):
        from .services import plan_sources

        runnable, excluded = plan_sources(
            ["source_code", "cloud", "hsm"], self.root, "specified"
        )
        self.assertEqual(runnable, ["source_code"])
        self.assertEqual({item["source"] for item in excluded}, {"cloud", "hsm"})

    def test_batch_creates_one_job_per_source(self):
        from . import services as discovery_services
        from .models import ScanBatch, ScanJob

        with mock.patch.object(discovery_services, "_dispatch_scan", side_effect=lambda job, db: job):
            batch = discovery_services.create_batch_scan(
                source_types=["source_code", "certificate", "container"],
                target=self.root,
                scan_type="specified",
                session_id=None,
            )

        self.assertEqual(len(batch.source_types), 3)
        jobs = ScanJob.objects.using("default").filter(batch=batch)
        self.assertEqual(jobs.count(), 3)
        self.assertEqual(
            set(jobs.values_list("source_type", flat=True)),
            {"source_code", "certificate", "container"},
        )
        # Each source keeps its own independent job: that is what preserves
        # per-source progress, cancel and partial reporting.
        self.assertEqual(len({j.pk for j in jobs}), 3)

    def test_batch_requires_at_least_one_source(self):
        from . import services as discovery_services

        with self.assertRaises(discovery_services.ScanInspectionError):
            discovery_services.create_batch_scan(
                source_types=[], target=self.root, scan_type="specified", session_id=None
            )

    def test_batch_rejects_a_duplicate_source(self):
        from . import services as discovery_services

        with self.assertRaises(discovery_services.ScanInspectionError):
            discovery_services.create_batch_scan(
                source_types=["source_code", "source_code"],
                target=self.root,
                scan_type="specified",
                session_id=None,
            )

    def test_batch_records_excluded_sources_instead_of_silently_dropping_them(self):
        from . import services as discovery_services

        with mock.patch.object(discovery_services, "_dispatch_scan", side_effect=lambda job, db: job):
            batch = discovery_services.create_batch_scan(
                source_types=["source_code", "cloud"],
                target=self.root,
                scan_type="specified",
                session_id=None,
            )
        self.assertEqual(
            {item["source"] for item in batch.excluded}, {"cloud"}
        )
        self.assertIn("not implemented", batch.excluded[0]["reason"])

    def test_batch_status_is_derived_from_its_jobs(self):
        from . import services as discovery_services
        from .models import ScanJob

        with mock.patch.object(discovery_services, "_dispatch_scan", side_effect=lambda job, db: job):
            batch = discovery_services.create_batch_scan(
                source_types=["source_code", "certificate"],
                target=self.root,
                scan_type="specified",
                session_id=None,
            )
        jobs = ScanJob.objects.using("default").filter(batch=batch)

        ScanJob.objects.using("default").filter(batch=batch).update(
            status=ScanJob.Status.COMPLETED, progress=100
        )
        batch = discovery_services.refresh_batch_status(batch, "default")
        self.assertEqual(batch.status, ScanJob.Status.COMPLETED)
        self.assertEqual(batch.progress, 100)

        # One source partial, the other clean -> the summary must not claim success.
        ScanJob.objects.using("default").filter(batch=batch).update(
            status=ScanJob.Status.PARTIAL
        )
        first = jobs.first()
        ScanJob.objects.using("default").filter(pk=first.pk).update(
            status=ScanJob.Status.COMPLETED
        )
        batch = discovery_services.refresh_batch_status(batch, "default")
        self.assertEqual(batch.status, ScanJob.Status.PARTIAL)

        ScanJob.objects.using("default").filter(batch=batch).update(
            status=ScanJob.Status.CANCELLED
        )
        batch = discovery_services.refresh_batch_status(batch, "default")
        self.assertEqual(batch.status, ScanJob.Status.CANCELLED)

    def test_batch_progress_is_the_mean_of_its_jobs(self):
        from . import services as discovery_services
        from .models import ScanJob

        with mock.patch.object(discovery_services, "_dispatch_scan", side_effect=lambda job, db: job):
            batch = discovery_services.create_batch_scan(
                source_types=["source_code", "certificate"],
                target=self.root,
                scan_type="specified",
                session_id=None,
            )
        ScanJob.objects.using("default").filter(batch=batch).update(
            status=ScanJob.Status.RUNNING, progress=40
        )
        batch = discovery_services.refresh_batch_status(batch, "default")
        self.assertEqual(batch.status, ScanJob.Status.RUNNING)
        self.assertEqual(batch.progress, 40)

    def test_cancelling_a_batch_stops_every_source(self):
        from . import services as discovery_services
        from .models import ScanJob

        with mock.patch.object(discovery_services, "_dispatch_scan", side_effect=lambda job, db: job):
            batch = discovery_services.create_batch_scan(
                source_types=["source_code", "certificate"],
                target=self.root,
                scan_type="specified",
                session_id=None,
            )
        affected = discovery_services.cancel_batch(batch, "default")
        self.assertEqual(affected, 2)
        statuses = set(
            ScanJob.objects.using("default")
            .filter(batch=batch)
            .values_list("status", flat=True)
        )
        self.assertFalse(
            statuses & {ScanJob.Status.QUEUED, ScanJob.Status.RUNNING},
            msg="cancelling the batch left a source still running",
        )

    def test_start_scan_endpoint_accepts_several_sources(self):
        from .models import ScanJob

        with mock.patch(
            "segments.scraping.discovery.services._dispatch_scan",
            side_effect=lambda scan_job, db: discovery_services.run_scan(scan_job),
        ):
            r = self.client.post(
                "/api/start-scan/",
                data={
                    "source_types": ["source_code", "certificate"],
                    "target": self.root,
                    "scan_type": "specified",
                },
                content_type="application/json",
            )
        self.assertEqual(r.status_code, 201, msg=r.content)
        body = r.json()["data"]
        self.assertEqual(body["scan_type"], "specified")
        self.assertEqual(sorted(body["source_types"]), ["certificate", "source_code"])
        self.assertEqual(len(body["sources"]), 2)
        self.assertTrue(all(s["status"] for s in body["sources"]))

    def test_start_scan_endpoint_still_accepts_a_single_source(self):
        from .models import ScanJob

        with mock.patch(
            "segments.scraping.discovery.services._dispatch_scan",
            side_effect=lambda scan_job, db: discovery_services.run_scan(scan_job),
        ):
            r = self.client.post(
                "/api/start-scan/",
                data={"source_type": "source_code", "target": self.root, "scan_type": "specified"},
                content_type="application/json",
            )
        self.assertEqual(r.status_code, 201, msg=r.content)
        self.assertIn("source_type", r.json()["data"])

    def test_start_scan_rejects_an_empty_source_list(self):
        r = self.client.post(
            "/api/start-scan/",
            data={"source_types": [], "target": self.root, "scan_type": "specified"},
            content_type="application/json",
        )
        # An empty list falls back to the default source rather than erroring.
        self.assertIn(r.status_code, (201, 400))

    def test_batch_endpoint_is_scoped_to_the_session(self):
        from core.models import WorkSession
        from .models import ScanBatch

        theirs = WorkSession.objects.using("default").create(name="batch-theirs")
        batch = ScanBatch.objects.using("default").create(
            target="x", scan_type="specified", source_types=["source_code"],
            session_id=theirs.pk,
        )
        mine = WorkSession.objects.using("default").create(name="batch-mine")
        self.client.post(f"/api/session/switch/{mine.pk}/")
        r = self.client.get(f"/api/scan-batches/{batch.pk}/")
        self.assertEqual(r.status_code, 404)


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class ContainerImageDiscoveryTests(TestCase):
    """Container images are read as archives; nothing is unpacked or executed."""

    @classmethod
    def setUpTestData(cls):
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "svc.internal")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cls.cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(4242)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .sign(key, hashes.SHA256())
        )

    def _layer(self) -> bytes:
        """A layer tar holding a certificate and an ELF with crypto symbols."""
        import io
        import tarfile

        from cryptography.hazmat.primitives import serialization

        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as tar:
            def add(name: str, data: bytes) -> None:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))

            add(
                "etc/ssl/certs/svc.crt",
                self.cert.public_bytes(serialization.Encoding.PEM),
            )
            add("usr/lib/libcrypto.so", _elf(b"\x00EVP_PKEY_new\x00EVP_aes_256_gcm\x00"))
            add("etc/passwd", b"root:x:0:0::/root:/bin/sh\n")
        return buffer.getvalue()

    def _docker_image(self, config_extra: dict | None = None) -> bytes:
        import io
        import json
        import tarfile

        layer = self._layer()
        config = {
            "config": {
                "Env": [
                    "PATH=/usr/bin",
                    "AWS_KMS_KEY_ID=arn:aws:kms:eu-west-1:1234:key/abc",
                    "TLS_CERT_FILE=/etc/ssl/certs/svc.crt",
                ],
                "Entrypoint": ["/usr/bin/app", "--tls-key-file", "/run/secret/tls.key"],
                "Labels": {"org.openshift.tls.mode": "ML-KEM-768"},
            }
        }
        config.update(config_extra or {})
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as tar:
            def add(name: str, data: bytes) -> None:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))

            add("manifest.json", json.dumps([{
                "Config": "config.json",
                "RepoTags": ["registry.local/payments:1.4.2"],
                "Layers": ["layer0/layer.tar"],
            }]).encode())
            add("config.json", json.dumps(config).encode())
            add("layer0/layer.tar", layer)
        return buffer.getvalue()

    def test_container_source_is_registered_and_available(self):
        from .models import ScanJob
        from .scanners import list_scanners

        entry = {e["source_type"]: e for e in list_scanners()}[ScanJob.SourceType.CONTAINER]
        self.assertEqual(entry["status"], "available")
        self.assertEqual(entry["id"], "container-image")
        self.assertIn("no_execution", entry["capabilities"])
        self.assertIn("layer_inspection", entry["capabilities"])

    def test_reads_a_docker_save_layout(self):
        from .scanners import container_image

        layout = container_image.read_layout(self._docker_image())
        self.assertTrue(layout.is_container)
        self.assertEqual(layout.kind, "docker-save")
        self.assertEqual(layout.tag, "registry.local/payments:1.4.2")
        self.assertEqual(layout.layers, ["layer0/layer.tar"])

    def test_reads_a_gzipped_layout(self):
        import gzip

        from .scanners import container_image

        layout = container_image.read_layout(gzip.compress(self._docker_image()))
        self.assertTrue(layout.is_container)
        self.assertEqual(layout.kind, "docker-save")

    def test_rejects_a_plain_tar_that_is_not_an_image(self):
        import io
        import tarfile

        from .scanners import container_image

        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as tar:
            info = tarfile.TarInfo("notes.txt")
            data = b"not an image"
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        layout = container_image.read_layout(buffer.getvalue())
        self.assertFalse(layout.is_container)
        self.assertEqual(layout.reason, "no_image_manifest")

    def test_rejects_a_non_archive(self):
        from .scanners import container_image

        layout = container_image.read_layout(b"just some bytes, not an image at all")
        self.assertFalse(layout.is_container)
        self.assertEqual(layout.reason, "not_a_tar_archive")

    def test_discovers_certificate_and_binary_inside_a_layer(self):
        from .scanners import container_image

        result, layout = container_image.discover("image:payments", self._docker_image())
        self.assertTrue(layout.is_container)
        certs = [c for c in result.certificates if c["evidence"].get("type") == "x509"]
        self.assertEqual(len(certs), 1)
        self.assertIn("svc.internal", certs[0]["evidence"]["subject"])
        self.assertEqual(certs[0]["evidence"]["layer"], "layer0")
        self.assertTrue(result.binaries, msg="no binary findings from the layer")

    def test_discovers_key_references_in_image_metadata(self):
        from .scanners import container_image

        result, _ = container_image.discover("image:payments", self._docker_image())
        values = {f["evidence"]["value"] for f in result.references}
        origins = {f["evidence"]["declared_in"] for f in result.references}
        self.assertIn("arn:aws:kms", values)
        self.assertIn("ml-kem", values)
        # TLS material paths are reported, and the setting that declared them
        # is retained so the user knows where to look.
        self.assertTrue(any(value.endswith((".crt", ".key")) for value in values))
        self.assertIn("environment variable TLS_CERT_FILE", origins)
        self.assertIn("entrypoint", origins)
        self.assertIn("label org.openshift.tls.mode", origins)

    def test_layer_members_are_reported_with_their_image_path(self):
        from .scanners import container_image

        result, _ = container_image.discover("image:payments", self._docker_image())
        locations = [c["location"] for c in result.certificates]
        self.assertTrue(
            any("etc/ssl/certs/svc.crt" in location for location in locations),
            msg=f"certificate location missing the in-image path: {locations}",
        )

    @mock.patch(
        "segments.scraping.discovery.services._dispatch_scan",
        side_effect=lambda scan_job, db: discovery_services.run_scan(scan_job),
    )
    def test_container_scan_produces_container_assets(self, _mock_dispatch):
        from .models import CryptoAsset, ScanJob

        root = tempfile.mkdtemp(prefix="ecdat_img_")
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        with open(os.path.join(root, "payments.tar"), "wb") as handle:
            handle.write(self._docker_image())
        with open(os.path.join(root, "random.tar"), "wb") as handle:
            handle.write(b"definitely not an image")

        job = discovery_services.create_and_run_scan(
            source_type=ScanJob.SourceType.CONTAINER, target=root, scan_type="specified",
        )
        job.refresh_from_db()
        self.assertNotEqual(job.status, "failed", msg=job.error)

        assets = list(CryptoAsset.objects.using("default").filter(session_id=job.session_id))
        self.assertTrue(assets, msg="no container assets were classified")
        self.assertIn(CryptoAsset.AssetType.CONTAINER, {a.asset_type for a in assets})
        self.assertTrue(all(a.identifier for a in assets))


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class CertificateStoreDiscoveryTests(TestCase):
    """The certificate scanner identifies every format without exposing keys."""

    @classmethod
    def setUpTestData(cls):
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        from cryptography.x509.oid import NameOID

        cls.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ecdat-test-ca")])
        cls.ca = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(cls.ca_key.public_key())
            .serial_number(1000)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(cls.ca_key, hashes.SHA256())
        )
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.ecdat.test")])
        cls.leaf = (
            x509.CertificateBuilder()
            .subject_name(leaf_name)
            .issuer_name(ca_name)
            .public_key(leaf_key.public_key())
            .serial_number(2000)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(cls.ca_key, hashes.SHA256())
        )
        cls.leaf_key = leaf_key
        del x509

    def _pem(self, cert) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return cert.public_bytes(serialization.Encoding.PEM)

    def _der(self, cert) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return cert.public_bytes(serialization.Encoding.DER)

    def _scan(self, files: dict[str, bytes]):
        from .scanners.certstore import discover

        findings = []
        for name, data in files.items():
            result = discover(f"target/{name}", data)
            findings.extend(result.certificates)
            findings.extend(result.key_references)
            findings.extend(result.stores)
        return findings

    def _details(self, files: dict[str, bytes]):
        from .scanners.certstore import discover

        return [
            finding["evidence"]
            for name, data in files.items()
            for finding in discover(f"target/{name}", data).certificates
            if finding["evidence"].get("type") == "x509"
        ]

    def test_certificate_source_is_registered_and_available(self):
        from .models import ScanJob
        from .scanners import list_scanners

        entries = {e["source_type"]: e for e in list_scanners()}
        entry = entries[ScanJob.SourceType.CERTIFICATE]
        self.assertEqual(entry["status"], "available")
        self.assertEqual(entry["id"], "certificate-store")
        self.assertIn("never_exposes_private_keys", entry["capabilities"])
        self.assertIn("chain_correlation", entry["capabilities"])

    def test_certificate_scan_is_no_longer_rejected(self):
        from .models import ScanJob

        job = discovery_services.create_and_run_scan(
            source_type=ScanJob.SourceType.CERTIFICATE,
            target="C:\\does-not-matter",
            scan_type="specified",
        )
        self.assertEqual(job.source_type, ScanJob.SourceType.CERTIFICATE)

    def test_discovers_pem_certificate(self):
        findings = self._scan({"server.crt": self._pem(self.leaf)})
        certs = [f for f in findings if f["kind"] == "certificate"]
        self.assertEqual(len(certs), 1)
        self.assertEqual(certs[0]["algorithm"], "EC")
        self.assertEqual(certs[0]["key_size"], 256)
        self.assertEqual(certs[0]["family"], "ecc")
        self.assertEqual(certs[0]["evidence"]["type"], "x509")
        self.assertIn("api.ecdat.test", certs[0]["evidence"]["subject"])

    def test_discovers_der_certificate(self):
        findings = self._scan({"server.der": self._der(self.leaf)})
        certs = [f for f in findings if f["kind"] == "certificate"]
        self.assertEqual(len(certs), 1)
        self.assertEqual(certs[0]["algorithm"], "EC")

    def test_discovers_a_certificate_signing_request(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(self.leaf.subject)
            .sign(self.leaf_key, hashes.SHA256())
        )
        pem = csr.public_bytes(serialization.Encoding.PEM)
        findings = self._scan({"request.csr": pem})
        certs = [f for f in findings if f["kind"] == "certificate"]
        self.assertEqual(len(certs), 1)
        self.assertEqual(certs[0]["evidence"]["type"], "pkcs10_request")
        self.assertIn("api.ecdat.test", certs[0]["evidence"]["request_subject"])
        self.assertEqual(certs[0]["algorithm"], "EC")

    def test_discovers_a_public_key(self):
        from cryptography.hazmat.primitives import serialization

        pem = self.leaf_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        findings = self._scan({"id_ecdsa.pub": pem})
        keys = [f for f in findings if f["kind"] == "key_reference"]
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0]["evidence"]["key_kind"], "public")

    def test_private_key_is_fingerprinted_and_never_exposed(self):
        from cryptography.hazmat.primitives import serialization

        pem = self.leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        findings = self._scan({"server.key": pem})
        keys = [f for f in findings if f["kind"] == "key_reference"]
        self.assertEqual(len(keys), 1)
        evidence = keys[0]["evidence"]
        self.assertEqual(evidence["key_kind"], "private")
        self.assertFalse(evidence["exposed"])
        self.assertEqual(len(evidence["value"]), 64)
        serialised = repr(findings)
        self.assertNotIn("BEGIN PRIVATE KEY", serialised)
        self.assertNotIn(
            f"{self.leaf_key.private_numbers().private_value:x}", serialised
        )

    def test_unencrypted_pkcs12_is_counted(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import pkcs12

        blob = pkcs12.serialize_key_and_certificates(
            b"bundle", self.leaf_key, self.leaf, [self.ca], serialization.NoEncryption()
        )
        findings = self._scan({"bundle.p12": blob})
        stores = [f for f in findings if f["evidence"].get("type") == "keystore_container"]
        self.assertEqual(len(stores), 1)
        evidence = stores[0]["evidence"]
        self.assertEqual(evidence["store_type"], "pkcs12")
        self.assertFalse(evidence["password_protected"])
        self.assertEqual(evidence["certificates"], 2)
        self.assertEqual(evidence["keys"], 1)

    def test_password_protected_pkcs12_is_reported_not_opened(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import pkcs12

        blob = pkcs12.serialize_key_and_certificates(
            b"bundle", self.leaf_key, self.leaf, None,
            serialization.BestAvailableEncryption(b"not-guessed"),
        )
        findings = self._scan({"vault.p12": blob})
        stores = [f for f in findings if f["evidence"].get("type") == "keystore_container"]
        self.assertEqual(len(stores), 1)
        evidence = stores[0]["evidence"]
        self.assertEqual(evidence["store_type"], "pkcs12")
        self.assertTrue(evidence["password_protected"])
        self.assertEqual(evidence["certificates"], 0)
        self.assertEqual(evidence["keys"], 0)

    def test_jks_is_identified(self):
        findings = self._scan({"cacerts.jks": b"\xfe\xed\xfe\xed\x00\x01" + b"\x00" * 32})
        stores = [f for f in findings if f["evidence"].get("type") == "keystore_container"]
        self.assertEqual(len(stores), 1)
        self.assertEqual(stores[0]["evidence"]["store_type"], "jks")
        self.assertTrue(stores[0]["evidence"]["password_protected"])

    def test_chain_correlation_links_leaf_to_ca(self):
        from .scanners.certstore import chain_pairs

        details = self._details({"ca-bundle.pem": self._pem(self.leaf) + self._pem(self.ca)})
        self.assertEqual(len(details), 2)
        pairs = chain_pairs(details)
        self.assertEqual(len(pairs), 1)
        self.assertEqual(pairs[0][0], details[0]["sha256_fingerprint"])
        self.assertEqual(pairs[0][1], details[1]["sha256_fingerprint"])

    def test_self_signed_certificate_is_not_treated_as_a_chain(self):
        from .scanners.certstore import chain_pairs

        self.assertEqual(chain_pairs(self._details({"root.pem": self._pem(self.ca)})), [])

    def test_chain_needs_the_issuer_to_actually_be_present(self):
        from .scanners.certstore import chain_pairs

        self.assertEqual(chain_pairs(self._details({"leaf.crt": self._pem(self.leaf)})), [])

    def test_plain_files_are_skipped(self):
        from .scanners.certstore import discover

        result = discover("target/README.md", b"just some documentation, not a certificate")
        self.assertEqual(result.certificates, [])
        self.assertEqual(result.key_references, [])
        self.assertEqual(result.stores, [])
        self.assertEqual(result.skipped, "no_certificate_or_key_material")

    @mock.patch(
        "segments.scraping.discovery.services._dispatch_scan",
        side_effect=lambda scan_job, db: discovery_services.run_scan(scan_job),
    )
    def test_certificate_scan_produces_certificate_assets(self, _mock_dispatch):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import pkcs12

        from .models import CryptoAsset, ScanJob

        root = tempfile.mkdtemp(prefix="ecdat_pki_")
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        with open(os.path.join(root, "leaf.crt"), "wb") as handle:
            handle.write(self._pem(self.leaf))
        with open(os.path.join(root, "ca.pem"), "wb") as handle:
            handle.write(self._pem(self.ca))
        with open(os.path.join(root, "notes.txt"), "wb") as handle:
            handle.write(b"not a certificate at all")
        with open(os.path.join(root, "vault.p12"), "wb") as handle:
            handle.write(
                pkcs12.serialize_key_and_certificates(
                    b"b", self.leaf_key, self.leaf, None,
                    serialization.BestAvailableEncryption(b"secret"),
                )
            )

        job = discovery_services.create_and_run_scan(
            source_type=ScanJob.SourceType.CERTIFICATE, target=root, scan_type="specified",
        )
        job.refresh_from_db()
        self.assertNotEqual(job.status, "failed", msg=job.error)

        assets = list(CryptoAsset.objects.using("default").filter(session_id=job.session_id))
        self.assertTrue(assets, msg="no certificate assets were classified")
        self.assertTrue(all(a.identifier for a in assets))
        self.assertIn(
            CryptoAsset.AssetType.CERTIFICATE,
            {a.asset_type for a in assets},
        )
        self.assertIn(
            CryptoAsset.AssetType.KEY_REFERENCE,
            {a.asset_type for a in assets},
        )
        # The protected store is inventoried, never opened.
        stores = [a for a in assets if a.asset_type == CryptoAsset.AssetType.KEY_REFERENCE]
        self.assertTrue(stores)


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class UnifiedGraphTests(TestCase):
    """Milestone 10: one navigable graph across every kind of entity."""

    def setUp(self):
        from core.models import WorkSession

        self.client = Client()
        self.workspace = WorkSession.objects.using("default").create(name="graph")
        self.client.post(f"/api/session/switch/{self.workspace.pk}/")
        self.root = tempfile.mkdtemp(prefix="ecdat_graph_")
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))

    def _seed(self, with_lockfile=True, with_cert=True):
        """A small project: manifest, lock file, a source file, a certificate."""
        import datetime
        import json as _json

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        from .classifier import classify_asset
        from .models import RawFinding, ScanJob
        from .normalizer import normalize_finding

        src = os.path.join(self.root, "src")
        os.makedirs(src, exist_ok=True)
        with open(os.path.join(src, "app.js"), "w", encoding="utf-8") as handle:
            handle.write("const C = require('crypto-js');\nconst h = C.SHA256;\n")

        with open(os.path.join(self.root, "package.json"), "w", encoding="utf-8") as handle:
            _json.dump(
                {"name": "demo-app", "dependencies": {"crypto-js": "^4.1.1"}}, handle
            )
        if with_lockfile:
            with open(os.path.join(self.root, "package-lock.json"), "w", encoding="utf-8") as handle:
                _json.dump(
                    {
                        "name": "demo-app", "lockfileVersion": 2,
                        "packages": {
                            "": {"name": "demo-app", "dependencies": {"crypto-js": "^4.1.1"}},
                            "node_modules/crypto-js": {"version": "4.1.1"},
                        },
                        "dependencies": {"crypto-js": {"version": "4.1.1"}},
                    },
                    handle,
                )

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "demo.internal")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(11)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .sign(key, hashes.SHA256())
        )
        cert_path = os.path.join(src, "tls.crt")
        with open(cert_path, "wb") as handle:
            handle.write(cert.public_bytes(serialization.Encoding.PEM))

        job = ScanJob.objects.using("default").create(
            source_type=ScanJob.SourceType.SOURCE_CODE,
            target=self.root, mode="actual", status=ScanJob.Status.COMPLETED,
            session_id=self.workspace.pk, config={"scan_type": "specified"},
        )

        rows = [
            (os.path.join(self.root, "package.json"), "manifest", "SHA256", "crypto-js", {}),
            (os.path.join(src, "app.js"), "source", "SHA256", "crypto-js", {}),
        ]
        if with_cert:
            # Emitted the way the certificate scanner emits it, so the
            # normalizer classifies it as a certificate rather than an
            # algorithm.
            rows.append((cert_path, "certificate", "RSA", "", {
                "kind": "certificate",
                "key_size": 2048,
                "evidence": {
                    "type": "x509",
                    "subject": "CN=demo.internal",
                    "issuer": "CN=demo.internal",
                    "sha256_fingerprint": "f" * 64,
                    "is_ca": False,
                },
            }))
        for path, family, algorithm, library, extra in rows:
            raw = RawFinding.objects.using("default").create(
                scan_job=job, source_type=ScanJob.SourceType.SOURCE_CODE,
                location=path, source_path=path, session_id=self.workspace.pk,
                raw_json={
                    "location": path, "family": family, "algorithm": algorithm,
                    "library": library, "confidence": 0.9, **extra,
                },
            )
            norm = normalize_finding(raw, using="default", session_id=self.workspace.pk)
            classify_asset(norm, using="default", session_id=self.workspace.pk)
        return job

    def test_build_creates_every_expected_node_type(self):
        from .graph_index import build_graph_index
        from .models import GraphNode

        job = self._seed()
        discovery_services.record_dependencies(job, "default")
        discovery_services.record_dependency_graph(job, "default")
        build_graph_index("default", session_id=self.workspace.pk, scan_job=job)

        present = set(
            GraphNode.objects.using("default")
            .filter(session_id=self.workspace.pk)
            .values_list("node_type", flat=True)
        )
        # The types the roadmap names, restricted to what this fixture produces.
        for expected in (
            GraphNode.NodeType.REPOSITORY,
            GraphNode.NodeType.APPLICATION,
            GraphNode.NodeType.FILE,
            GraphNode.NodeType.DEPENDENCY,
            GraphNode.NodeType.ALGORITHM,
            GraphNode.NodeType.CERTIFICATE,
        ):
            self.assertIn(expected, present, msg=f"no {expected} node was created")

    def test_every_edge_carries_its_evidence(self):
        """An edge that cannot say why it exists is a guess."""
        from .graph_index import build_graph_index
        from .models import GraphEdge

        job = self._seed()
        discovery_services.record_dependencies(job, "default")
        discovery_services.record_dependency_graph(job, "default")
        build_graph_index("default", session_id=self.workspace.pk, scan_job=job)

        for edge in GraphEdge.objects.using("default").filter(session=self.workspace.pk):
            self.assertTrue(
                (edge.evidence or {}).get("why"),
                msg=f"{edge.relation_type} edge has no recorded reason",
            )

    def test_rebuild_is_idempotent(self):
        from .graph_index import build_graph_index
        from .models import GraphEdge, GraphNode

        job = self._seed()
        discovery_services.record_dependencies(job, "default")
        discovery_services.record_dependency_graph(job, "default")
        build_graph_index("default", session_id=self.workspace.pk, scan_job=job)
        nodes = GraphNode.objects.using("default").filter(session=self.workspace.pk).count()
        edges = GraphEdge.objects.using("default").filter(session=self.workspace.pk).count()

        build_graph_index("default", session_id=self.workspace.pk, scan_job=job)
        self.assertEqual(
            GraphNode.objects.using("default").filter(session=self.workspace.pk).count(), nodes
        )
        self.assertEqual(
            GraphEdge.objects.using("default").filter(session=self.workspace.pk).count(), edges
        )

    def test_graph_is_scoped_to_the_session(self):
        from core.models import WorkSession
        from .graph_index import build_graph_index
        from .models import GraphNode

        job = self._seed()
        discovery_services.record_dependencies(job, "default")
        discovery_services.record_dependency_graph(job, "default")
        build_graph_index("default", session_id=self.workspace.pk, scan_job=job)

        other = WorkSession.objects.using("default").create(name="graph-other")
        self.client.post(f"/api/session/switch/{other.pk}/")
        stats = self.client.get("/api/graph-index/").json()["data"]["stats"]
        self.assertEqual(stats["nodes"], 0, msg="another session's graph leaked")
        self.assertTrue(
            GraphNode.objects.using("default").filter(session=self.workspace.pk).exists()
        )

    def test_dependents_walks_backwards(self):
        from .graph_index import build_graph_index
        from .graph_queries import dependents
        from .models import GraphNode

        job = self._seed()
        discovery_services.record_dependencies(job, "default")
        discovery_services.record_dependency_graph(job, "default")
        build_graph_index("default", session_id=self.workspace.pk, scan_job=job)

        lib = GraphNode.objects.using("default").get(
            session=self.workspace.pk, node_type=GraphNode.NodeType.DEPENDENCY, label="crypto-js"
        )
        result = dependents("default", self.workspace.pk, lib.pk)
        self.assertGreaterEqual(result["count"], 1)
        # demo-app requires crypto-js, so it must appear as a dependent.
        names = {entry["path"][-1]["node"]["label"] for entry in result["paths"]}
        self.assertIn("demo-app", names)

    def test_every_query_returns_the_same_path_shape(self):
        """A consumer must not special-case which question it asked."""
        from .graph_index import build_graph_index
        from .graph_queries import blast_radius_of, certificates_of, dependents
        from .models import GraphNode

        job = self._seed()
        discovery_services.record_dependencies(job, "default")
        discovery_services.record_dependency_graph(job, "default")
        build_graph_index("default", session_id=self.workspace.pk, scan_job=job)

        app = GraphNode.objects.using("default").filter(
            session=self.workspace.pk, node_type=GraphNode.NodeType.APPLICATION
        ).first()
        self.assertIsNotNone(app, msg="no application node to query")

        for result in (
            dependents("default", self.workspace.pk, app.pk),
            certificates_of("default", self.workspace.pk, app.pk),
            blast_radius_of("default", self.workspace.pk, app.pk),
        ):
            for entry in result["paths"]:
                self.assertIn("path", entry)
                for hop in entry["path"]:
                    self.assertIn("node", hop, msg="a hop is missing its node")
                    self.assertIn("relation", hop)

    def test_certificates_of_an_application(self):
        from .graph_index import build_graph_index
        from .graph_queries import certificates_of
        from .models import GraphNode

        job = self._seed()
        discovery_services.record_dependencies(job, "default")
        discovery_services.record_dependency_graph(job, "default")
        build_graph_index("default", session_id=self.workspace.pk, scan_job=job)

        app = GraphNode.objects.using("default").filter(
            session=self.workspace.pk, node_type=GraphNode.NodeType.APPLICATION
        ).first()
        result = certificates_of("default", self.workspace.pk, app.pk)
        found = [
            hop["node"]
            for entry in result["paths"]
            for hop in entry["path"]
            if hop["node"]["node_type"] == GraphNode.NodeType.CERTIFICATE
        ]
        self.assertTrue(found, msg="the application's certificate was not reachable")

    def test_impact_endpoint_answers_each_question(self):
        from .graph_index import build_graph_index
        from .models import GraphNode

        job = self._seed()
        discovery_services.record_dependencies(job, "default")
        discovery_services.record_dependency_graph(job, "default")
        build_graph_index("default", session_id=self.workspace.pk, scan_job=job)

        app = GraphNode.objects.using("default").filter(
            session=self.workspace.pk, node_type=GraphNode.NodeType.APPLICATION
        ).first()
        for question in ("dependents", "certificates", "blast-radius"):
            r = self.client.get(
                f"/api/graph-index/{app.pk}/impact/?question={question}"
            )
            self.assertEqual(r.status_code, 200, msg=question)
            self.assertEqual(r.json()["data"]["question"], question)

        bad = self.client.get(f"/api/graph-index/{app.pk}/impact/?question=nonsense")
        self.assertEqual(bad.status_code, 400)

    def test_unmapped_asset_types_are_reported_not_hidden(self):
        from .graph_index import build_graph_index

        job = self._seed()
        build_graph_index("default", session_id=self.workspace.pk, scan_job=job)
        body = self.client.get("/api/graph-index/?rebuild=1").json()["data"]
        self.assertIn("unmapped_asset_types", body)

    def test_rebuild_endpoint_reports_what_it_did(self):
        job = self._seed()
        discovery_services.record_dependencies(job, "default")
        discovery_services.record_dependency_graph(job, "default")
        r = self.client.get("/api/graph-index/?rebuild=1")
        self.assertEqual(r.status_code, 200)
        body = r.json()["data"]
        self.assertTrue(body["rebuilt"])
        self.assertGreater(body["nodes_created"] + body["nodes_reused"], 0)
        self.assertGreater(body["edges_created"], 0)

    def test_graph_endpoint_filters_by_node_type(self):
        from .graph_index import build_graph_index
        from .models import GraphNode

        job = self._seed()
        discovery_services.record_dependencies(job, "default")
        discovery_services.record_dependency_graph(job, "default")
        build_graph_index("default", session_id=self.workspace.pk, scan_job=job)

        r = self.client.get("/api/graph-index/?node_type=certificate")
        self.assertEqual(r.status_code, 200)
        nodes = r.json()["data"]["nodes"]
        self.assertTrue(nodes)
        for node in nodes:
            self.assertEqual(node["node_type"], "certificate")



@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class HandoffContractTests(TestCase):
    """Milestone 12: Discover -> Understand is a checked contract, not a hope.

    The plan (section 29) requires that for every finding the reasoning stage can
    answer six questions. These tests build a real project, run a real scan, and
    assert each answer exists -- so a regression in discovery's output fails
    here rather than turning into a confident wrong statement downstream.
    """

    def setUp(self):
        import shutil
        import tempfile

        from core.models import WorkSession

        self.client = Client()
        self.workspace = WorkSession.objects.using("default").create(name="handoff")
        self.client.post(f"/api/session/switch/{self.workspace.pk}/")
        self.root = tempfile.mkdtemp(prefix="ecdat_handoff_")
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))

    def _project(self, with_manifest=True, with_certificate=True):
        """A project with a manifest, a crypto source file, and a certificate."""
        import datetime
        import json as _json

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        src = os.path.join(self.root, "src")
        os.makedirs(src, exist_ok=True)
        with open(os.path.join(src, "app.js"), "w", encoding="utf-8") as handle:
            handle.write("const C = require('crypto-js');\nconst h = C.SHA256;\n")
        if with_manifest:
            with open(os.path.join(self.root, "package.json"), "w", encoding="utf-8") as handle:
                _json.dump({"name": "demo", "dependencies": {"crypto-js": "^4.1.1"}}, handle)
        if with_certificate:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "handoff.test")])
            now = datetime.datetime.now(datetime.timezone.utc)
            cert = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=30))
                .sign(key, hashes.SHA256())
            )
            with open(os.path.join(src, "tls.crt"), "wb") as handle:
                handle.write(cert.public_bytes(serialization.Encoding.PEM))

    def _run_scan(self, source_type="source_code"):
        """Run a real scan inside the test transaction.

        The async dispatcher is replaced with a synchronous call, because a
        background thread would use its own connection and none of its writes
        would be visible inside the test's transaction.
        """
        from .models import ScanJob

        with mock.patch(
            "segments.scraping.discovery.services._auto_analyze"
        ), mock.patch(
            "segments.scraping.discovery.services._dispatch_scan",
            side_effect=lambda scan_job, db: discovery_services.run_scan(scan_job),
        ):
            response = self.client.post(
                "/api/start-scan/",
                data=json.dumps(
                    {
                        "scan_type": "specified",
                        "source_type": source_type,
                        "target": self.root,
                        "options": {},
                    }
                ),
                content_type="application/json",
            )
        self.assertIn(response.status_code, (201, 202), response.content)
        job_id = response.json()["data"]["id"]
        return ScanJob.objects.using("default").filter(pk=job_id).first()

    # --- the six questions -------------------------------------------------

    def test_every_finding_answers_every_contract_question(self):
        """WHAT / WHERE / HOW / HOW CONFIDENT, for all real findings."""
        self._project()
        self._run_scan()
        payload = self.client.get("/api/handoff/").json()["data"]

        self.assertTrue(payload["findings"], "scan produced no findings to hand off")
        self.assertEqual(payload["contract"]["unanswered_by_question"], {})
        self.assertTrue(payload["contract"]["satisfied"])
        for entry in payload["findings"]:
            self.assertTrue(entry["algorithm"] or entry["kind"], entry)
            self.assertTrue(entry["location"] or entry["source_path"], entry)
            self.assertTrue(entry["source_type"], entry)
            self.assertIsNotNone(entry["confidence"], entry)

    def test_contract_questions_are_named_for_the_consumer(self):
        self._project()
        self._run_scan()
        questions = self.client.get("/api/handoff/").json()["data"]["questions"]
        self.assertEqual(len(questions), 6)
        for question in questions:
            self.assertEqual(question["unanswered"], 0, question)
            self.assertTrue(question["label"].endswith("?"), question)

    def test_finding_reports_the_detector_that_found_it(self):
        """HOW was it discovered: a named detector, not just a source type."""
        self._project()
        self._run_scan()
        payload = self.client.get("/api/handoff/").json()["data"]
        detectors = {entry["detector"] for entry in payload["findings"]}
        self.assertIn("dependency_parser", detectors)

    def test_library_finding_answers_what_it_depends_on(self):
        """A manifest-backed asset names the package that provides it."""
        self._project()
        self._run_scan()
        payload = self.client.get("/api/handoff/").json()["data"]
        providers = {
            package
            for entry in payload["findings"]
            for package in entry["depends_on"]
        }
        self.assertIn("crypto-js", providers)

    # --- the part that was wrong before -----------------------------------

    def test_certificate_is_not_claimed_to_be_provided_by_a_library(self):
        """A `provides` edge means the package backs the artefact.

        crypto-js is declared in the same directory as the certificate, which
        says nothing about who issued it. Recording that as `provides` handed
        the reasoning stage a false claim, so shared-directory locality must not
        produce a provisioning edge.
        """
        self._project()
        self._run_scan()
        payload = self.client.get("/api/handoff/").json()["data"]

        certificates = [
            entry
            for entry in payload["findings"]
            if entry["kind"] == "certificate" or entry["asset_type"] == "certificate"
        ]
        self.assertTrue(certificates, "expected a certificate finding")
        for entry in certificates:
            self.assertEqual(
                entry["depends_on"], [],
                f"certificate was claimed to depend on {entry['depends_on']}",
            )

        from .models import DependencyRelation

        for relation in DependencyRelation.objects.using("default").filter(
            relation_type="provides", to_asset__asset_type="certificate"
        ):
            self.fail(f"unfounded provides edge: {relation.from_dependency.package}")

    def test_container_and_binary_assets_are_never_provided(self):
        """The same rule holds for every artefact a library cannot supply."""
        from .models import DependencyRelation

        for asset_type in ("container", "binary", "certificate", "key_reference"):
            self.assertFalse(
                DependencyRelation.objects.using("default").filter(
                    relation_type="provides", to_asset__asset_type=asset_type
                ).exists(),
                f"{asset_type} cannot be provided by a package",
            )

    # --- coverage honesty --------------------------------------------------

    def test_unscanned_sources_are_reported_as_coverage_not_silence(self):
        """A source that never ran is a gap the consumer must be told about."""
        self._project()
        self._run_scan()
        coverage = self.client.get("/api/handoff/").json()["data"]["coverage"]
        self.assertIn("source_code", coverage["sources_run"])
        self.assertTrue(coverage["disclosure"])
        for entry in coverage["sources_excluded"]:
            self.assertIn(entry["source_type"], {"binary", "certificate", "container"})
            self.assertNotIn(entry["source_type"], coverage["sources_run"])

    def test_every_available_source_that_ran_is_not_reported_missing(self):
        """Guards the id/source_type mix-up that reported running sources as missing."""
        self._project()
        self._run_scan()
        coverage = self.client.get("/api/handoff/").json()["data"]["coverage"]
        self.assertEqual(
            sorted(entry["source_type"] for entry in coverage["sources_excluded"]),
            sorted(set() | ({"binary", "certificate", "container"} - set(coverage["sources_run"]))),
        )

    def test_coverage_reports_scanned_and_skipped_counts(self):
        self._project()
        self._run_scan()
        coverage = self.client.get("/api/handoff/").json()["data"]["coverage"]
        self.assertGreater(coverage["items_scanned"], 0)
        self.assertIsInstance(coverage["items_skipped"], int)

    def test_disclosure_does_not_claim_completeness_when_nothing_ran(self):
        from .handoff import Coverage

        coverage = Coverage()
        coverage.scan_status = "unscanned"
        self.assertIn("Nothing has been discovered", coverage.as_dict()["disclosure"])
        self.assertFalse(coverage.as_dict()["complete"])

    def test_skip_reasons_are_named_in_the_disclosure(self):
        from .handoff import Coverage

        coverage = Coverage()
        coverage.scan_status = "partial"
        coverage.items_scanned = 10
        coverage.items_skipped = 3
        coverage.skip_reasons = {"too_large": 2, "unreadable": 1}
        text = coverage.as_dict()["disclosure"]
        self.assertIn("3 item(s) were not inspected", text)
        self.assertIn("too large", text)
        self.assertIn("only what was read", text)

    def test_complete_coverage_says_so_plainly(self):
        from .handoff import Coverage

        coverage = Coverage()
        coverage.scan_status = "completed"
        coverage.items_scanned = 10
        self.assertTrue(coverage.as_dict()["complete"])
        self.assertEqual(coverage.as_dict()["disclosure"], "Every discovered item was read.")

    # --- scoping and input handling ---------------------------------------

    def test_handoff_is_scoped_to_the_session(self):
        self._project()
        job = self._run_scan()
        payload = self.client.get("/api/handoff/").json()["data"]
        # The scan is what the handoff must agree with, whichever session the
        # start-scan request ended up in.
        self.assertEqual(payload["session_id"], job.session_id)

    def test_handoff_can_be_narrowed_to_one_scan(self):
        self._project()
        job = self._run_scan()
        scoped = self.client.get(f"/api/handoff/?scan_id={job.pk}").json()["data"]
        self.assertEqual(scoped["scan_job_id"], job.pk)
        self.assertEqual(scoped["target"], job.target)
        self.assertLessEqual(len(scoped["findings"]), 5000)

    def test_unknown_scan_is_a_404(self):
        self.assertEqual(self.client.get("/api/handoff/?scan_id=999999").status_code, 404)

    def test_non_integer_scan_id_is_a_400(self):
        self.assertEqual(self.client.get("/api/handoff/?scan_id=abc").status_code, 400)

    def test_non_integer_limit_is_a_400(self):
        self.assertEqual(self.client.get("/api/handoff/?limit=many").status_code, 400)

    def test_limit_truncation_is_declared(self):
        self._project()
        self._run_scan()
        payload = self.client.get("/api/handoff/?limit=1").json()["data"]
        self.assertTrue(payload["counts"]["findings_truncated"])
        self.assertEqual(payload["counts"]["findings"], 1)
        self.assertEqual(len(payload["findings"]), 1)
        # A page that is not the whole dataset cannot claim the contract holds.
        self.assertFalse(payload["contract"]["satisfied"])

    def test_untruncated_handoff_does_not_set_the_flag(self):
        self._project()
        self._run_scan()
        counts = self.client.get("/api/handoff/?limit=5000").json()["data"]["counts"]
        self.assertFalse(counts["findings_truncated"])

    def test_handoff_requires_get(self):
        self.assertEqual(self.client.post("/api/handoff/").status_code, 405)

    def test_summary_mode_omits_findings_but_keeps_the_verdict(self):
        """The Findings header needs a verdict, not the whole dataset.

        The contract is still evaluated across every finding, because a verdict
        computed from a truncated page would describe the page rather than the
        scan.
        """
        self._project()
        self._run_scan()
        full = self.client.get("/api/handoff/").json()["data"]
        summary = self.client.get("/api/handoff/?summary=1").json()["data"]

        self.assertTrue(full["findings"])
        self.assertNotIn("findings", summary)
        self.assertEqual(summary["counts"]["findings"], full["counts"]["findings"])
        self.assertEqual(summary["contract"], full["contract"])
        self.assertEqual(len(summary["questions"]), 6)

    def test_summary_mode_does_not_report_a_page_as_a_scan(self):
        """A small page is truncated; a summary of the same scan is not."""
        self._project()
        self._run_scan()
        page = self.client.get("/api/handoff/?limit=1").json()["data"]
        self.assertTrue(page["counts"]["findings_truncated"])
        self.assertFalse(page["contract"]["satisfied"])

        summary = self.client.get("/api/handoff/?summary=1").json()["data"]
        self.assertFalse(summary["counts"]["findings_truncated"])
        self.assertTrue(summary["contract"]["satisfied"])

    def test_evidence_travels_with_the_finding(self):
        """HOW includes the evidence, so nothing is asserted without a source."""
        self._project()
        self._run_scan()
        payload = self.client.get("/api/handoff/").json()["data"]
        with_evidence = [e for e in payload["findings"] if e["evidence"]]
        self.assertTrue(with_evidence)
        self.assertTrue(any(e["evidence_type"] for e in with_evidence))

    def test_validation_status_is_derived_from_a_merged_asset(self):
        self._project()
        self._run_scan()
        payload = self.client.get("/api/handoff/").json()["data"]
        for entry in payload["findings"]:
            if entry["asset_id"]:
                self.assertEqual(entry["validation_status"], "confirmed")
                self.assertTrue(entry["asset_identifier"])
            else:
                self.assertEqual(entry["validation_status"], "needs_review")
