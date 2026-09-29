import os
import sys
import django

os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings'
django.setup()

from django.utils import timezone
from core.models import WorkSession
from segments.scraping.discovery.models import ScanJob, RawFinding, NormalizedFinding, CryptoAsset
from segments.scraping.discovery.scanners.crypto_artefact import CryptoArtefactScanner
from segments.scraping.discovery.scanners.base import ScanContext
from segments.scraping.discovery.normalizer import normalize_finding
from segments.scraping.discovery.classifier import classify_asset
from segments.ml.analysis.models import AnalysisRun
from segments.ml.analysis.runner import _run_pipeline
from segments.mitigation.mitigation.models import MitigationPlan
from segments.mitigation.mitigation.planner import generate_plan
from segments.reporting.reports.report_builder import build_report, _evaluate_invariants, _build_canonical_classification_ledger
from segments.reporting.reports.pdf_renderer import render_pdf

TARGET_PATH = r"C:\Users\Lenovo\Downloads\ECDAT_URGENT_TEST"

def run_pipeline():
    print(f"=== STEP 1: Running Discovery Scan on {TARGET_PATH} ===")
    session = WorkSession.objects.create(name=f"Urgent-Test-{int(timezone.now().timestamp())}")
    db = "default"

    scan_job = ScanJob.objects.create(
        session=session,
        target=TARGET_PATH,
        source_type=ScanJob.SourceType.SOURCE_CODE,
        status=ScanJob.Status.RUNNING,
        started_at=timezone.now(),
    )

    context = ScanContext(on_progress=lambda *args, **kwargs: None, is_cancelled=lambda: False)
    scanner = CryptoArtefactScanner(scan_job)
    raw_findings = scanner.run(context)
    print(f"  Scanner detected {len(raw_findings)} raw finding occurrences.")

    ingested = scanner.ingest(raw_findings)
    print(f"  Ingested {ingested} RawFinding rows.")

    qs = RawFinding.objects.filter(scan_job=scan_job)
    norm_count = 0
    for raw in qs:
        norm = normalize_finding(raw, using=db, session_id=session.pk)
        classify_asset(norm, using=db, session_id=session.pk)
        norm_count += 1
    print(f"  Normalized and classified {norm_count} findings.")

    scan_job.status = ScanJob.Status.COMPLETED
    scan_job.progress = 100
    scan_job.finished_at = timezone.now()
    scan_job.save()

    canonical_assets = list(CryptoAsset.objects.filter(session_id=session.pk))
    print(f"  Created {len(canonical_assets)} canonical CryptoAssets in session {session.pk}:")
    for ca in canonical_assets:
        print(f"    - {ca.name} (Algo: {ca.algorithm}, KeySize: {ca.key_size}, Env: {ca.environment})")

    print(f"\n=== STEP 2: Running Analysis Pipeline ===")
    run = AnalysisRun.objects.create(
        scan_job=scan_job,
        session=session,
        status=AnalysisRun.Status.QUEUED,
        progress=0,
    )
    _run_pipeline(run, db=db, mode="actual")
    run.refresh_from_db()
    print(f"  AnalysisRun #{run.pk} status: {run.status}")
    stats = (run.executive_summary or {}).get("stats", {})
    print(f"  Run Stats: {stats}")

    print(f"\n=== STEP 3: Generating Mitigation Plan ===")
    plan = MitigationPlan.objects.filter(run=run).first()
    if not plan:
        plan = MitigationPlan.objects.create(
            run=run,
            session_id=session.pk,
            status=MitigationPlan.Status.PENDING,
            progress=0,
        )
    generate_plan(plan.pk, mode="actual")
    plan.refresh_from_db()
    print(f"  MitigationPlan #{plan.pk} status: {plan.status}")
    p_summary = (plan.document or {}).get("summary", {})
    print(f"  Mitigation Summary: Wave 1={p_summary.get('wave1')}, Wave 2={p_summary.get('wave2')}, Wave 3={p_summary.get('wave3')}")

    print(f"\n=== STEP 4: Building Enterprise Post-Quantum Risk Report ===")
    rep = build_report(sid=session.pk, db=db)
    data = rep["data"]
    canonical_records = _build_canonical_classification_ledger(data)

    print(f"  Canonical Classification Records Count: {len(canonical_records)}")
    rsa_asset = next((r for r in canonical_records if "RSA" in r["algorithm"]), None)
    if rsa_asset:
        print(f"  RSA Asset Found: {rsa_asset['asset_id']} - {rsa_asset['algorithm']}")
        print(f"    - Risk Tier:       {rsa_asset['risk_tier']}")
        print(f"    - Priority:        {rsa_asset['priority']}")
        print(f"    - Remediation Wave:{rsa_asset['remediation_wave']}")
        print(f"    - HNDL Status:     {rsa_asset['hndl_status']}")
        print(f"    - HNDL Exposure:   {rsa_asset['hndl_exposure']}")
        print(f"    - Public Exposure: {rsa_asset['public_exposure']}")
        print(f"    - Mosca Deficit:   {rsa_asset['mosca_deficit']} years")
        print(f"    - Mosca Status:    {rsa_asset['mosca_status']}")
        print(f"    - Urgency Reason:  {rsa_asset['urgency_reason']}")

        assert rsa_asset["priority"] == "URGENT", f"Expected URGENT, got {rsa_asset['priority']}"
        assert rsa_asset["risk_tier"] == "URGENT", f"Expected URGENT, got {rsa_asset['risk_tier']}"
        assert rsa_asset["remediation_wave"] == 1, f"Expected Wave 1, got {rsa_asset['remediation_wave']}"
        assert rsa_asset["hndl_exposure"] == "HIGH", f"Expected HIGH, got {rsa_asset['hndl_exposure']}"
        assert rsa_asset["hndl_status"] == "APPLICABLE", f"Expected APPLICABLE, got {rsa_asset['hndl_status']}"
        assert rsa_asset["mosca_deficit"] > 0, f"Expected positive deficit, got {rsa_asset['mosca_deficit']}"
        assert rsa_asset["public_exposure"] is True, f"Expected True, got {rsa_asset['public_exposure']}"
        print("  >>> RSA-1024 REGRESSION ASSERTIONS ALL PASSED! <<<")

    print(f"\n=== STEP 5: Invariant Evaluation ===")
    invariants = _evaluate_invariants(data, canonical_records)
    for inv in invariants:
        status = "PASS" if inv["passed"] else "FAIL"
        print(f"  [{status}] {inv['name']}: {inv['detail']}")
        assert inv["passed"], f"Invariant failed: {inv['name']} - {inv['detail']}"

    print(f"\n=== STEP 6: PDF Rendering ===")
    html = rep["html"]
    pdf_filename = rep["filename"]
    pdf_bytes = render_pdf(html)
    pdf_path = os.path.join(r"C:\Users\Lenovo\Desktop\ECDAT\ECDAT\backend", pdf_filename)
    with open(pdf_path, "wb") as f:
        f.write(pdf_bytes)
    print(f"  Report PDF generated successfully: {pdf_path} ({len(pdf_bytes)} bytes)")

    # Verify HTML does not contain stale contradictions
    assert "URGENT PRIORITY = 0" not in html and "URGENT Priority</div>0" not in html
    print("  Report verified: No 'URGENT Priority: 0' found.")
    print("\nALL CONSISTENCY CHECKS SUCCESSFULLY PASSED!")

if __name__ == "__main__":
    run_pipeline()
