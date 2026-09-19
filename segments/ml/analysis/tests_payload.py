"""Tests for the analysis CBOM-ready payload builder."""

from django.test import TestCase, override_settings

from segments.scraping.discovery.classifier import classify_asset
from segments.scraping.discovery.models import RawFinding, ScanJob
from segments.scraping.discovery.normalizer import normalize_finding

from .payload_builder import (
    build_analysis_payload,
    default_raw_system_context,
    finding_id_for,
    parse_finding_id,
)


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
class PayloadBuilderTests(TestCase):
    def _make_job(self, target="work/app"):
        return ScanJob.objects.using("default").create(
            source_type="source_code",
            target=target,
            mode="actual",
            status="completed",
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

    def test_payload_repo_block(self):
        job = self._make_job(target="myrepo/backend")
        payload = build_analysis_payload(job)
        self.assertEqual(payload["repository"]["name"], "myrepo/backend")
        self.assertEqual(payload["repository"]["url"], "")

    def test_rsa_finding_maps_to_pipeline_schema(self):
        job = self._make_job()
        raw, norm = self._seed_raw(
            job,
            {
                "location": "work/auth/TlsConfig.java",
                "family": "rsa",
                "algorithm": "RSA",
                "confidence": 0.9,
                "raw": {"matches": 3, "strings": ["BEGIN RSA PRIVATE KEY", "RSA"]},
            },
        )
        payload = build_analysis_payload(job)
        self.assertEqual(len(payload["findings"]), 1)
        f = payload["findings"][0]
        self.assertEqual(f["id"], f"N{norm.pk}")
        self.assertEqual(f["file"], "work/auth/TlsConfig.java")
        self.assertEqual(f["detected"], "RSA")
        self.assertEqual(f["code"], "BEGIN RSA PRIVATE KEY; RSA")
        self.assertEqual(f["family"], "rsa")
        self.assertEqual(f["confidence"], 0.9)
        self.assertEqual(f["parameters"]["key_size"], norm.key_size)
        self.assertEqual(f["parameters"]["curve"], norm.curve or "")

    def test_code_evidence_synthesized_when_no_strings(self):
        job = self._make_job()
        raw, _ = self._seed_raw(
            job,
            {
                "location": "svc/crypto/hash.py",
                "family": "hash",
                "algorithm": "SHA256",
                "confidence": 0.7,
            },
        )
        payload = build_analysis_payload(job)
        self.assertEqual(len(payload["findings"]), 1)
        code = payload["findings"][0]["code"]
        self.assertTrue(code)
        self.assertIn("SHA256", code)
        self.assertIn("svc/crypto/hash.py", code)

    def test_family_unknown_still_passes_family_through(self):
        job = self._make_job()
        _, norm = self._seed_raw(
            job,
            {
                "location": "~/.ssh/id_ed25519",
                "family": "unknown",
                "algorithm": "OpenSSH-private",
                "confidence": 0.6,
            },
        )
        payload = build_analysis_payload(job)
        f = payload["findings"][0]
        self.assertEqual(f["family"], "unknown")
        self.assertEqual(f["detected"], "OpenSSH-private")
        self.assertEqual(f["id"], f"N{norm.pk}")

    def test_max_findings_caps_output(self):
        job = self._make_job()
        for i in range(3):
            self._seed_raw(
                job,
                {
                    "location": f"file_{i}.java",
                    "family": "rsa",
                    "algorithm": "RSA",
                    "raw": {"strings": [f"key {i}"]},
                },
            )
        payload = build_analysis_payload(job, max_findings=2)
        self.assertEqual(len(payload["findings"]), 2)

    def test_empty_scan_yields_no_findings(self):
        job = self._make_job()
        payload = build_analysis_payload(job)
        self.assertEqual(payload["findings"], [])

    def test_default_context_shape(self):
        ctx = default_raw_system_context()
        for key in ("application", "data", "network", "business_context"):
            self.assertIn(key, ctx)
        self.assertFalse(ctx["network"]["publicly_accessible"])
        self.assertFalse(ctx["network"]["internet_facing"])
        self.assertFalse(ctx["network"]["external_users"])

    def test_finding_id_for_none_pk(self):
        self.assertEqual(finding_id_for(NormalizedFindingProxy(pk=None)), "N-1")

    def test_parse_finding_id(self):
        self.assertEqual(parse_finding_id("N12"), 12)
        self.assertIsNone(parse_finding_id("5"))
        self.assertIsNone(parse_finding_id(""))


class NormalizedFindingProxy:
    def __init__(self, pk):
        self.pk = pk