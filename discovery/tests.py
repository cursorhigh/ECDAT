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


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class EndToEndScanTests(TestCase):
    """POST /api/start-scan/ runs the full pipeline on a real folder."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="ecdat_e2e_")
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))
        with open(os.path.join(self.root, "app.py"), "w") as f:
            f.write("import hashlib\nhashlib.md5(b'x')\nhashlib.sha256(b'x')\n")
        self.client = Client()

    @mock.patch("discovery.services._auto_analyze")
    def test_start_scan_produces_assets_via_pipeline(self, _mock_auto):
        r = self.client.post(
            "/api/start-scan/",
            data=json.dumps(
                {"scan_type": "specified", "source_type": "source_code",
                 "target": self.root, "options": {}}
            ),
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 201)
        body = r.json()
        self.assertEqual(body["status"], "completed")
        self.assertGreaterEqual(body["findings_count"], 1)

        from .models import NormalizedFinding
        nfs = NormalizedFinding.objects.filter(raw_finding__scan_job_id=body["id"])
        self.assertGreaterEqual(nfs.count(), 1)
        self.assertTrue(nfs.filter(family="hash").exists())


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
        import discovery.scanners.platform as plat

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

    def test_scan_limits_merge_config_overrides(self):
        base = get_scan_limits(_fake_job("quick", "quick"))
        self.assertEqual(base.max_files, 10_000)
        self.assertEqual(base.max_depth, 12)
        overridden = get_scan_limits(_fake_job("quick", "quick", {"max_files": 99, "max_depth": 3}))
        self.assertEqual(overridden.max_files, 99)
        self.assertEqual(overridden.max_depth, 3)


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
        import discovery.scanners.platform as plat

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
        from discovery.models import ScanJob

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

        with patch("discovery.services.create_and_run_scan", side_effect=fake_create):
            r = self.client.post(
                "/api/start-scan/",
                data=json.dumps(
                    {"scan_type": "specified", "source_type": "source_code",
                     "target": "/opt/app", "options": {}}
                ),
                content_type="application/json",
            )

        self.assertEqual(r.status_code, 201)
        sid = r.json()["session"]["id"]
        self.assertTrue(sid)
        self.assertTrue(WorkSession.objects.using("default").filter(pk=sid).exists())
        self.assertEqual(produced["session_id"], sid)

        job = ScanJob.objects.using("default").get(session_id=sid)
        r = self.client.get("/api/scans/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(job.pk, [x["id"] for x in r.data["results"]])

        info = self.client.get("/api/session/info/").json()
        self.assertEqual(info["session_id"], sid)
        self.assertEqual(info["scope"], "session")

    @mock.patch("discovery.services._auto_analyze")
    def test_scan_data_auto_session_and_isolation(self, _mock_auto):
        from core.models import WorkSession
        from core.sessions import scope
        from discovery.models import CryptoAsset, NormalizedFinding, ScanJob

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
        sid = r.json()["session"]["id"]
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
        self.assertEqual([x["id"] for x in r.data["results"]], [job.pk])

        self.client.post("/api/session/switch/0/")
        r = self.client.get("/api/scans/")
        self.assertIn(job.pk, [x["id"] for x in r.data["results"]])


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class AutoAnalysisTests(TestCase):
    """A finished scan automatically stages analysis (pending a context choice)."""

    def _job(self, mode="actual", findings_count=1, **kw):
        from discovery.models import ScanJob

        return ScanJob.objects.using("default").create(
            source_type="source_code",
            target="auto-q",
            mode=mode,
            status=ScanJob.Status.COMPLETED,
            findings_count=findings_count,
            **kw,
        )

    @mock.patch("analysis.runner.pending_analysis")
    def test_auto_analyze_stages_pending_analysis(self, mock_pending):
        job = self._job()

        discovery_services._auto_analyze(job)

        mock_pending.assert_called_once()
        self.assertIs(mock_pending.call_args.args[0], job)

    @mock.patch("analysis.runner.pending_analysis")
    def test_auto_analyze_skips_when_no_data(self, mock_pending):
        job = self._job(findings_count=0)

        discovery_services._auto_analyze(job)

        mock_pending.assert_not_called()

    @mock.patch("analysis.runner.pending_analysis")
    def test_auto_analyze_skips_duplicate(self, mock_pending):
        from analysis.models import AnalysisRun

        job = self._job()
        AnalysisRun.objects.using("default").create(
            scan_job=job, mode="actual", status=AnalysisRun.Status.QUEUED
        )

        discovery_services._auto_analyze(job)

        mock_pending.assert_not_called()

    @mock.patch("analysis.runner.pending_analysis")
    def test_auto_analyze_skips_demo(self, mock_pending):
        job = self._job(mode="demo")

        discovery_services._auto_analyze(job)

        mock_pending.assert_not_called()

    @mock.patch.dict(os.environ, {"ECDAT_AUTO_ANALYSE": "0"})
    @mock.patch("analysis.runner.pending_analysis")
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
        ).json()

    @mock.patch("discovery.services._auto_analyze")
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
        data = r.json()
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

    @mock.patch("discovery.services._auto_analyze")
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

        from discovery.models import AssetRelation

        rels = list(AssetRelation.objects.using("default").values_list("session_id", flat=True))
        self.assertEqual(len(rels), 1)              # one relate edge, from the 2-RSA session
        self.assertEqual(rels[0], first_session)    # stamped with the owning session

        r = self.client.get("/api/graph/")
        self.assertEqual(r.json()["asset_relations"], [])   # other session's edge stays hidden

        self.client.post("/api/session/switch/0/")
        r = self.client.get("/api/graph/")
        self.assertGreaterEqual(len(r.json()["asset_relations"]), 1)  # visible as all data

    @mock.patch("discovery.services._auto_analyze")
    def test_graph_correlate_endpoint_builds_edges(self, _mock_auto):
        self._ingest([
            {"location": "k1.java", "family": "rsa", "algorithm": "RSA", "key_size": 2048,
             "confidence": 0.9},
            {"location": "k2.java", "family": "rsa", "algorithm": "RSA", "key_size": 4096,
             "confidence": 0.7},
        ])
        from discovery.models import AssetRelation

        AssetRelation.objects.using("default").all().delete()   # simulate "correlation didn't happen"

        r = self.client.post("/api/graph/correlate/", content_type="application/json")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertGreaterEqual(body.get("created"), 1)         # edges rebuilt on demand
        self.assertGreaterEqual(body.get("total"), 1)           # and now visible to the graph

    @mock.patch("discovery.services._auto_analyze")
    def test_graph_data_scopes_to_active_session(self, _mock_auto):
        first_session = self._ingest([
            {"location": "a.js", "family": "rsa", "algorithm": "RSA", "key_size": 2048,
             "confidence": 0.9},
        ])["session"]["id"]
        second_session = self._ingest([
            {"location": "b.py", "family": "hash", "algorithm": "SHA256", "confidence": 0.9},
        ])["session"]["id"]
        self.assertNotEqual(first_session, second_session)

        from discovery.models import NormalizedFinding

        first_ids = set(
            NormalizedFinding.objects.using("default")
            .filter(session_id=first_session).values_list("pk", flat=True)
        )
        first_ids = {(f"f{pk}") for pk in first_ids}

        r = self.client.get("/api/graph/")
        data = r.json()
        node_keys = {f"f{f['id']}" for f in data["findings"]}
        self.assertTrue(node_keys)                      # active session has its own findings
        self.assertTrue(node_keys.isdisjoint(first_ids))  # other session's findings excluded
