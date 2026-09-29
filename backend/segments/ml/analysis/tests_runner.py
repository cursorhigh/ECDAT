"""Tests for the analysis runner pipeline and API endpoints."""

import json
import os
from unittest import mock

from django.test import Client, TestCase, override_settings

from core.modes import active_mode
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
        from core.models import WorkSession

        self.session = WorkSession.objects.using("default").create(name="test-session")
        self.client.post(f"/api/session/switch/{self.session.pk}/")

    def _make_job(self, target="work/app", status="completed"):
        return ScanJob.objects.using("default").create(
            session=self.session,
            source_type="source_code",
            target=target,
                        status=status,
            config={"scan_type": "specified"},
        )

    def _seed_raw(self, job, raw_json, location=None):
        if location is None:
            location = raw_json.get("location", "")
        raw = RawFinding.objects.using("default").create(
            scan_job=job,
            session=self.session,
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
            session=self.session,
                        status=status,
            input_payload=payload if payload is not None else build_analysis_payload(job),
            raw_system_context=default_raw_system_context(job),
        )

    def test_capped_payload_declares_its_truncation(self):
        """A capped payload must never look like a complete one."""
        job = self._make_job()
        for index in range(5):
            self._seed_raw(
                job,
                {
                    "location": f"src/Module{index}.java",
                    "family": "rsa",
                    "algorithm": "RSA",
                    "confidence": 0.9,
                },
            )

        full = build_analysis_payload(job)
        self.assertEqual(len(full["findings"]), 5)
        self.assertNotIn("truncation", full)

        capped = build_analysis_payload(job, max_findings=2)
        self.assertEqual(len(capped["findings"]), 2)
        self.assertEqual(
            capped["truncation"],
            {"truncated": True, "analysed": 2, "available": 5, "limit": 2},
        )

    def test_truncation_is_exposed_on_the_run_detail(self):
        job = self._make_job()
        for index in range(4):
            self._seed_raw(
                job,
                {
                    "location": f"src/File{index}.java",
                    "family": "rsa",
                    "algorithm": "RSA",
                    "confidence": 0.9,
                },
            )
        run = self._make_run(
            job, payload=build_analysis_payload(job, max_findings=2)
        )
        with mock.patch("segments.ml.analysis.runner._auto_mitigation"):
            execute_analysis(run.pk, "actual")

        r = self.client.get(f"/api/analysis/{run.pk}/")
        self.assertEqual(r.status_code, 200)
        body = r.json()["data"]
        self.assertEqual(body["findings_count"], 2)
        self.assertTrue(body["truncation"]["truncated"])
        self.assertEqual(body["truncation"]["available"], 4)
        self.assertEqual(body["truncation"]["analysed"], 2)

    def test_uncapped_run_reports_no_truncation(self):
        job = self._make_job()
        self._seed_raw(
            job,
            {"location": "a/RSA.java", "family": "rsa", "algorithm": "RSA", "confidence": 0.9},
        )
        run = self._make_run(job)
        with mock.patch("segments.ml.analysis.runner._auto_mitigation"):
            execute_analysis(run.pk, "actual")

        body = self.client.get(f"/api/analysis/{run.pk}/").json()["data"]
        self.assertIsNone(body["truncation"])

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

    def setUp(self):
        from core.models import WorkSession

        self.session = WorkSession.objects.using("default").create(name="test-session")

    def _pending_client(self):
        """A client bound to this test's session, as a browser would be."""
        from django.test import Client

        client = Client()
        client.post(f"/api/session/switch/{self.session.pk}/")
        return client

    def _pending_job(self):
        return ScanJob.objects.using("default").create(
            session=self.session,
            source_type="source_code",
            target="pending/app",
                        status="completed",
            findings_count=1,
        )

    def test_pending_analysis_creates_awaiting_run(self):
        job = ScanJob.objects.using("default").create(
            source_type="source_code",
            target="pending/app",
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

    @mock.patch("segments.ml.analysis.runner._dispatch")
    def test_auto_continue_queues_with_default_after_timeout(self, mock_dispatch):
        job = ScanJob.objects.using("default").create(
            source_type="source_code",
            target="pending/app",
                        status="completed",
            findings_count=1,
        )
        with mock.patch("segments.ml.analysis.runner.threading.Thread"):
            run = pending_analysis(job)

        _auto_continue(run.pk, active_mode(), "default", 0)

        run.refresh_from_db()
        self.assertEqual(run.status, "queued")
        self.assertIsNone(run.await_until)
        mock_dispatch.assert_called_once()
        self.assertEqual(mock_dispatch.call_args.args[0].pk, run.pk)

    @mock.patch("segments.ml.analysis.runner._dispatch")
    def test_continue_pending_uses_custom_context(self, mock_dispatch):
        job = ScanJob.objects.using("default").create(
            source_type="source_code",
            target="pending/app",
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

    def test_awaiting_endpoint_lists_pending_run(self):
        job = self._pending_job()
        with mock.patch("segments.ml.analysis.runner.threading.Thread"):
            pending_analysis(job)

        r = self._pending_client().get("/api/analysis/awaiting/")
        self.assertEqual(r.status_code, 200)
        rows = r.json()["data"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["scan_job_id"], job.pk)
        self.assertGreater(rows[0]["seconds_left"], 0)

    @mock.patch("segments.ml.analysis.runner.threading.Thread")
    def test_api_start_without_context_commits_the_defaults(self, _mock_thread):
        """The "Use defaults" button: redeem a parked run with no context.

        This is the path the frontend's dismiss button takes -- POST start with
        no `raw_system_context`. It had no test, which is how the button shipped
        wired to a plain close: nothing proved the backend would actually
        dispatch, so the run sat in AWAITING_CONTEXT until the deadline timer
        happened to fire.

        The point is that the run *leaves* AWAITING_CONTEXT and keeps the context
        it was parked with.
        """
        job = self._pending_job()
        with mock.patch("segments.ml.analysis.runner.threading.Thread"):
            run = pending_analysis(job)
        parked_context = run.raw_system_context
        self.assertEqual(run.status, AnalysisRun.Status.AWAITING_CONTEXT)

        r = self._pending_client().post(
            "/api/analysis/start/",
            data=json.dumps({"scan_job": job.pk}),
            content_type="application/json",
        )

        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["data"]["id"], run.pk)
        self.assertEqual(r.json()["data"]["status"], AnalysisRun.Status.QUEUED)

        run.refresh_from_db()
        self.assertEqual(run.status, AnalysisRun.Status.QUEUED)
        self.assertIsNone(run.await_until)
        # Untouched, so the assessment is reasoned from the conservative values
        # the run was created with rather than anything invented here.
        self.assertEqual(run.raw_system_context, parked_context)

    @mock.patch("segments.ml.analysis.runner.threading.Thread")
    def test_api_start_redemption_reuses_awaiting_run(self, _mock_thread):
        job = self._pending_job()
        run = pending_analysis(job)

        custom = default_raw_system_context(job)
        custom["data"]["types"] = ["test_data"]
        r = self._pending_client().post(
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


"""CycloneDX / CBOM export tests (Milestone 11)."""

import json
import os
import shutil
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

from django.test import Client, TestCase, override_settings

from segments.ml.cbom import cyclonedx
from segments.ml.cbom.export import (
    CBOMUnavailable,
    UnsupportedCBOMFormat,
    build_export,
)

NS = "{http://cyclonedx.org/schema/bom/1.6}"

# Enumerations from the CycloneDX 1.6 schema. Asserted against rather than
# assumed, because an invalid enum value makes the whole document unusable.
PRIMITIVES = {
    "drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke",
    "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other", "unknown",
}
CRYPTO_FUNCTIONS = {
    "generate", "keygen", "encrypt", "decrypt", "digest", "tag", "keyderive",
    "sign", "verify", "encapsulate", "decapsulate", "other", "unknown",
}
COMPONENT_TYPES = {
    "application", "framework", "library", "container", "platform",
    "operating-system", "device", "device-driver", "firmware", "file",
    "machine-learning-model", "data", "cryptographic-asset",
}
ASSET_TYPES = {"algorithm", "certificate", "protocol", "related-crypto-material"}
HASH_ALGS = {"SHA-256", "SHA-384", "SHA-512", "SHA-1"}


class CycloneDXConversionTests(TestCase):
    """The serialiser, exercised without touching the database."""

    def _doc(self, assets, repository=None):
        return {
            "format": "ECDAT-CBOM",
            "version": "1.0",
            "generated_at": "2026-01-01T00:00:00Z",
            "repository": repository or {"name": "ECDAT inventory", "url": ""},
            "summary": {"total_assets": len(assets), "by_family": {"rsa": 1}},
            "crypto_assets": assets,
        }

    def test_document_declares_the_required_envelope(self):
        document = cyclonedx.to_cyclonedx(self._doc([]))
        self.assertEqual(document["bomFormat"], "CycloneDX")
        self.assertEqual(document["specVersion"], "1.6")
        self.assertTrue(document["serialNumber"].startswith("urn:uuid:"))
        self.assertEqual(document["version"], 1)
        for key in ("metadata", "components", "dependencies"):
            self.assertIn(key, document)
        self.assertIn("timestamp", document["metadata"])
        self.assertIn("components", document["metadata"]["tools"])

    def test_every_component_type_is_valid_for_the_spec(self):
        assets = [
            {"name": "AES-256", "family": "aes", "algorithm": "AES", "key_size": 256},
            {"name": "crypto-js", "kind": "library", "library": "crypto-js",
             "library_version": "4.1.1"},
            {"name": "app.py", "kind": "source_code", "location": "app.py"},
            {"name": "svc cert", "kind": "certificate", "family": "certificate",
             "algorithm": "RSA", "key_size": 2048},
        ]
        document = cyclonedx.to_cyclonedx(self._doc(assets))
        self.assertEqual(len(document["components"]), 4)
        for component in document["components"]:
            self.assertIn(component["type"], COMPONENT_TYPES)

    def test_primitives_and_functions_are_spec_valid(self):
        assets = [
            {"name": "SHA-256", "family": "hash", "algorithm": "SHA256", "key_size": 256},
            {"name": "AES-128", "family": "aes", "algorithm": "AES", "key_size": 128},
            {"name": "ECDH", "family": "ecc", "algorithm": "ECDH", "key_size": 256,
             "curve": "P-256"},
            {"name": "Diffie-Hellman", "family": "dh", "algorithm": "DH", "key_size": 2048},
            {"name": "ML-KEM-768", "family": "pqc", "algorithm": "ML-KEM-768"},
            {"name": "HMAC", "family": "mac", "algorithm": "HMAC-SHA256"},
            {"name": "???", "family": "unknown"},
        ]
        document = cyclonedx.to_cyclonedx(self._doc(assets))
        for component in document["components"]:
            properties = component["cryptoProperties"]
            self.assertIn(properties["assetType"], ASSET_TYPES)
            algorithm = properties.get("algorithmProperties")
            if not algorithm:
                continue
            self.assertIn(algorithm["primitive"], PRIMITIVES)
            for function in algorithm.get("cryptoFunctions") or []:
                self.assertIn(function, CRYPTO_FUNCTIONS)

    def test_pqc_primitive_is_inferred_from_the_algorithm_name(self):
        kem = cyclonedx._primitive_for("pqc", "ML-KEM-768")
        signature = cyclonedx._primitive_for("pqc", "ML-DSA-65")
        self.assertEqual(kem, "kem")
        self.assertEqual(signature, "signature")

    def test_classical_security_level_is_a_strength_not_a_key_length(self):
        """RSA-2048 is 112 bits of strength; reporting 2048 would be wrong."""
        self.assertEqual(cyclonedx._classical_strength("rsa", 2048), 112)
        self.assertEqual(cyclonedx._classical_strength("rsa", 4096), 152)
        self.assertEqual(cyclonedx._classical_strength("ecc", 256), 128)
        self.assertEqual(cyclonedx._classical_strength("aes", 256), 256)
        self.assertEqual(cyclonedx._classical_strength("hash", 256), 128)
        # Unknown sizes yield nothing rather than a guess.
        self.assertIsNone(cyclonedx._classical_strength("rsa", 1234))
        self.assertIsNone(cyclonedx._classical_strength("aes", None))

    def test_unknown_strength_is_omitted_not_defaulted_to_zero(self):
        """CycloneDX consumers read 0 as a measurement; absence means unknown."""
        assets = [{"name": "AES", "family": "aes", "algorithm": "AES", "key_size": 999}]
        document = cyclonedx.to_cyclonedx(self._doc(assets))
        properties = document["components"][0]["cryptoProperties"]["algorithmProperties"]
        self.assertNotIn("classicalSecurityLevel", properties)
        self.assertEqual(properties["executionEnvironment"], "software-plain-ram")

    def test_nist_quantum_level_only_for_named_pqc(self):
        self.assertEqual(cyclonedx._nist_level("ML-KEM-768"), 3)
        self.assertIsNone(cyclonedx._nist_level("AES-256"))

    def test_certificate_properties_and_hash_are_carried(self):
        assets = [
            {
                "name": "svc",
                "kind": "certificate",
                "family": "certificate",
                "algorithm": "RSA",
                "key_size": 2048,
                "evidence": {
                    "subject": "CN=svc.internal",
                    "issuer": "CN=internal-ca",
                    "not_before": "2026-01-01T00:00:00Z",
                    "not_after": "2027-01-01T00:00:00Z",
                    "serial": "0A1B",
                    "sha256_fingerprint": "ab" * 32,
                },
            }
        ]
        document = cyclonedx.to_cyclonedx(self._doc(assets))
        component = document["components"][0]
        crypto = component["cryptoProperties"]
        self.assertEqual(crypto["assetType"], "certificate")
        self.assertEqual(
            crypto["certificateProperties"]["subjectName"], "CN=svc.internal"
        )
        self.assertEqual(crypto["certificateProperties"]["serialNumber"], "0A1B")
        self.assertEqual(component["hashes"][0]["alg"], "SHA-256")
        self.assertIn(component["hashes"][0]["alg"], HASH_ALGS)

    def test_key_material_is_typed_not_exposed(self):
        assets = [
            {"name": "id_rsa", "kind": "key_reference", "family": "rsa",
             "algorithm": "RSA", "key_size": 4096, "line": 1}
        ]
        document = cyclonedx.to_cyclonedx(self._doc(assets))
        crypto = document["components"][0]["cryptoProperties"]
        self.assertEqual(crypto["assetType"], "related-crypto-material")
        material = crypto["relatedCryptoMaterialProperties"]
        self.assertEqual(material["type"], "public-key")
        self.assertEqual(material["size"], 4096)
        # A key reference must never carry key bytes into an export.
        serialised = json.dumps(document)
        self.assertNotIn("BEGIN PRIVATE KEY", serialised)
        self.assertNotIn("BEGIN PUBLIC KEY", serialised)

    def test_protocol_mode_is_read_from_the_protocol_field(self):
        assets = [
            {"name": "TLS", "kind": "protocol", "family": "unknown",
             "algorithm": "AES", "key_size": 256, "protocol": "TLS 1.3 CBC"}
        ]
        document = cyclonedx.to_cyclonedx(self._doc(assets))
        crypto = document["components"][0]["cryptoProperties"]
        self.assertEqual(crypto["protocolProperties"]["type"], "tls")
        self.assertEqual(crypto["algorithmProperties"]["mode"], "cbc")

    def test_ecdat_facts_survive_as_properties(self):
        assets = [
            {"name": "AES-256", "family": "aes", "algorithm": "AES", "key_size": 256,
             "library": "cryptography", "library_version": "42.0",
             "location": "src/app.py", "confidence": 0.95,
             "validation_status": "confirmed", "evidence_type": "binary_symbol",
             "detector": "binary_inspector", "explanation": "linked symbol"}
        ]
        document = cyclonedx.to_cyclonedx(self._doc(assets))
        properties = {
            prop["name"]: prop["value"] for prop in document["components"][0]["properties"]
        }
        self.assertEqual(properties["ecdat:family"], "aes")
        self.assertEqual(properties["ecdat:key-size"], "256")
        self.assertEqual(properties["ecdat:library"], "cryptography")
        self.assertEqual(properties["ecdat:location"], "src/app.py")
        self.assertEqual(properties["ecdat:validation-status"], "confirmed")
        self.assertEqual(properties["ecdat:confidence"], "0.95")
        self.assertEqual(properties["ecdat:evidence-type"], "binary_symbol")
        self.assertEqual(properties["ecdat:explanation"], "linked symbol")

    def test_summary_survives_export(self):
        """`needs review` has no CycloneDX equivalent and must not be lost."""
        document = cyclonedx.to_cyclonedx(self._doc([]))
        properties = {
            prop["name"]: prop["value"]
            for prop in document["metadata"]["properties"]
        }
        self.assertEqual(properties["ecdat:total_assets"], "0")
        self.assertEqual(properties["ecdat:family-count:rsa"], "1")

    def test_bom_refs_are_unique_and_stable(self):
        assets = [
            {"name": "AES", "family": "aes", "algorithm": "AES", "key_size": 256},
            {"name": "AES", "family": "aes", "algorithm": "AES", "key_size": 256},
        ]
        first = cyclonedx.to_cyclonedx(self._doc(assets))
        second = cyclonedx.to_cyclonedx(self._doc(assets))
        refs = [c["bom-ref"] for c in first["components"]]
        self.assertEqual(len(refs), len(set(refs)), msg="bom-refs must be unique")
        # Same input, same refs: two exports stay diffable.
        self.assertEqual(refs, [c["bom-ref"] for c in second["components"]])

    def test_identifier_is_preferred_for_a_stable_ref(self):
        assets = [{"name": "x", "family": "aes", "identifier": "abc123"}]
        document = cyclonedx.to_cyclonedx(self._doc(assets))
        self.assertEqual(document["components"][0]["bom-ref"], "urn:ecdat:asset:abc123")

    def test_every_component_has_a_dependency_entry(self):
        """The spec expects a complete entry per component, leaves included."""
        assets = [
            {"name": "A", "family": "aes", "algorithm": "AES", "identifier": "a"},
            {"name": "B", "family": "hash", "algorithm": "SHA256", "identifier": "b"},
        ]
        document = cyclonedx.to_cyclonedx(
            self._doc(assets),
            dependency_edges=[
                ("urn:ecdat:asset:a", "urn:ecdat:asset:b"),
            ],
        )
        entries = {entry["ref"]: entry for entry in document["dependencies"]}
        self.assertIn("urn:ecdat:repository", entries)
        for ref in ("urn:ecdat:asset:a", "urn:ecdat:asset:b"):
            self.assertIn(ref, entries)
        self.assertEqual(entries["urn:ecdat:asset:a"]["dependsOn"], ["urn:ecdat:asset:b"])
        self.assertEqual(entries["urn:ecdat:asset:b"]["dependsOn"], [])

    def test_self_referencing_edges_are_dropped(self):
        assets = [{"name": "A", "family": "aes", "identifier": "a"}]
        document = cyclonedx.to_cyclonedx(
            self._doc(assets),
            dependency_edges=[("urn:ecdat:asset:a", "urn:ecdat:asset:a")],
        )
        entry = next(
            e for e in document["dependencies"] if e["ref"] == "urn:ecdat:asset:a"
        )
        self.assertEqual(entry["dependsOn"], [])

    def test_xml_is_well_formed_and_namespaced(self):
        assets = [
            {"name": "AES-256", "family": "aes", "algorithm": "AES", "key_size": 256},
            {"name": "svc", "kind": "certificate", "family": "certificate",
             "algorithm": "RSA", "key_size": 2048,
             "evidence": {"subject": "CN=svc", "sha256_fingerprint": "cd" * 32}},
        ]
        document = cyclonedx.to_cyclonedx(self._doc(assets))
        xml = cyclonedx.to_cyclonedx_xml(document)
        root = ET.fromstring(xml)
        self.assertTrue(root.tag.startswith(NS))
        self.assertEqual(root.find(f"{NS}bomFormat").text, "CycloneDX")
        self.assertEqual(root.find(f"{NS}specVersion").text, "1.6")
        components = root.find(f"{NS}components")
        self.assertEqual(len(components.findall(f"{NS}component")), 2)
        crypto = components.findall(f"{NS}component")[0].find(f"{NS}cryptoProperties")
        self.assertIsNotNone(crypto)
        self.assertEqual(
            crypto.find(f"{NS}assetType").text,
            cyclonedx._crypto_asset_type("aes", ""),
        )
        self.assertIsNotNone(crypto.find(f"{NS}algorithmProperties"))
        # Round-trips: parsing the XML yields the same component count.
        self.assertEqual(
            len(ET.fromstring(xml).find(f"{NS}components").findall(f"{NS}component")), 2
        )

    def test_xml_escapes_hostile_values(self):
        assets = [
            {"name": '<script>alert("x")</script>', "family": "aes",
             "algorithm": "AES", "key_size": 256, "library": "a & b"}
        ]
        document = cyclonedx.to_cyclonedx(self._doc(assets))
        xml = cyclonedx.to_cyclonedx_xml(document)
        self.assertNotIn("<script>", xml)
        root = ET.fromstring(xml)
        names = [c.find(f"{NS}name").text for c in root.find(f"{NS}components")]
        self.assertEqual(names, ['<script>alert("x")</script>'])

    def test_empty_document_is_still_valid(self):
        document = cyclonedx.to_cyclonedx(self._doc([]))
        self.assertEqual(document["components"], [])
        self.assertEqual(
            [e["ref"] for e in document["dependencies"]], ["urn:ecdat:repository"]
        )


class CBOMExportTests(TestCase):
    """The export endpoint, against real discovered data."""

    def setUp(self):
        from core.models import WorkSession
        from segments.scraping.discovery.classifier import classify_asset
        from segments.scraping.discovery.models import RawFinding, ScanJob
        from segments.scraping.discovery.normalizer import normalize_finding

        self.client = Client()
        self.workspace = WorkSession.objects.using("default").create(name="cbom")
        self.client.post(f"/api/session/switch/{self.workspace.pk}/")
        self.root = tempfile.mkdtemp(prefix="ecdat_cbom_")
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))

        self.job = ScanJob.objects.using("default").create(
            source_type=ScanJob.SourceType.SOURCE_CODE,
            target=self.root, status=ScanJob.Status.COMPLETED,
            session_id=self.workspace.pk, config={"scan_type": "specified"},
        )
        for index, (family, algorithm, size) in enumerate(
            [("aes", "AES", 256), ("hash", "SHA256", 256), ("rsa", "RSA", 2048)]
        ):
            path = os.path.join(self.root, f"file{index}.py")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("# crypto\n")
            raw = RawFinding.objects.using("default").create(
                scan_job=self.job, source_type=ScanJob.SourceType.SOURCE_CODE,
                location=path, source_path=path, session_id=self.workspace.pk,
                raw_json={
                    "location": path, "family": family, "algorithm": algorithm,
                    "key_size": size, "confidence": 0.9,
                },
            )
            norm = normalize_finding(raw, using="default", session_id=self.workspace.pk)
            classify_asset(norm, using="default", session_id=self.workspace.pk)

    def test_cyclonedx_json_export(self):
        r = self.client.get("/api/analysis/cbom/?format=cyclonedx-json")
        self.assertEqual(r.status_code, 200, msg=r.content)
        self.assertIn("cyclonedx", r["Content-Type"])
        self.assertIn("attachment", r["Content-Disposition"])
        document = json.loads(r.content)
        self.assertEqual(document["bomFormat"], "CycloneDX")
        self.assertTrue(document["components"])

    def test_cyclonedx_xml_export(self):
        r = self.client.get("/api/analysis/cbom/?format=cyclonedx-xml")
        self.assertEqual(r.status_code, 200, msg=r.content)
        root = ET.fromstring(r.content)
        self.assertEqual(root.find(f"{NS}bomFormat").text, "CycloneDX")

    def test_native_export(self):
        r = self.client.get("/api/analysis/cbom/?format=ecdat")
        self.assertEqual(r.status_code, 200)
        document = json.loads(r.content)
        self.assertEqual(document["format"], "ECDAT-CBOM")
        self.assertGreater(document["summary"]["total_assets"], 0)

    def test_unknown_format_is_rejected_with_guidance(self):
        r = self.client.get("/api/analysis/cbom/?format=pdf")
        self.assertEqual(r.status_code, 400)
        self.assertIn("cyclonedx", r.json()["message"])

    def test_empty_scope_reports_409_not_an_empty_file(self):
        """A CBOM with nothing in it should say so, not download a stub."""
        from core.models import WorkSession
        from segments.scraping.discovery.models import ScanJob

        empty = WorkSession.objects.using("default").create(name="cbom-empty")
        ScanJob.objects.using("default").create(
            source_type=ScanJob.SourceType.SOURCE_CODE, target="x",             status=ScanJob.Status.COMPLETED, session_id=empty.pk,
        )
        self.client.post(f"/api/session/switch/{empty.pk}/")
        r = self.client.get("/api/analysis/cbom/?format=cyclonedx-json")
        self.assertEqual(r.status_code, 409)
        # The API wraps responses in a standard envelope; the message carries the text.
        self.assertIn("No cryptographic assets", r.json()["message"])

    def test_export_is_session_scoped(self):
        from core.models import WorkSession
        from segments.scraping.discovery.models import ScanJob

        other = WorkSession.objects.using("default").create(name="cbom-other")
        ScanJob.objects.using("default").create(
            source_type=ScanJob.SourceType.SOURCE_CODE, target="y",             status=ScanJob.Status.COMPLETED, session_id=other.pk,
        )
        self.client.post(f"/api/session/switch/{other.pk}/")
        r = self.client.get("/api/analysis/cbom/?format=cyclonedx-json")
        self.assertEqual(r.status_code, 409, msg="another session's assets leaked")

    def test_run_scoped_export_only_includes_that_scan(self):
        from segments.ml.analysis.models import AnalysisRun

        run = AnalysisRun.objects.using("default").create(
            scan_job=self.job, status=AnalysisRun.Status.COMPLETED,
            session_id=self.workspace.pk,
        )
        r = self.client.get(f"/api/analysis/{run.pk}/cbom/?format=cyclonedx-json")
        self.assertEqual(r.status_code, 200, msg=r.content)

    def test_run_from_another_session_is_not_found(self):
        from core.models import WorkSession
        from segments.ml.analysis.models import AnalysisRun

        other = WorkSession.objects.using("default").create(name="cbom-theirs")
        run = AnalysisRun.objects.using("default").create(
            scan_job=self.job, status=AnalysisRun.Status.COMPLETED,
            session_id=other.pk,
        )
        self.client.post(f"/api/session/switch/{self.workspace.pk}/")
        r = self.client.get(f"/api/analysis/{run.pk}/cbom/?format=cyclonedx-json")
        self.assertEqual(r.status_code, 404)

    def test_build_export_rejects_an_unknown_format(self):
        with self.assertRaises(UnsupportedCBOMFormat):
            build_export("docx", db="default", session_id=self.workspace.pk)
