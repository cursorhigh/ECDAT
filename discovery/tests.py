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

    def test_start_scan_produces_assets_via_pipeline(self):
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
