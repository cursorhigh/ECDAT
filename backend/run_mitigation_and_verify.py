import os
import django

os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings'
django.setup()

from segments.ml.analysis.models import AnalysisRun
from segments.mitigation.mitigation.models import MitigationPlan
from segments.mitigation.mitigation.planner import generate_plan
from segments.reporting.reports.report_builder import build_report, _evaluate_invariants
from segments.reporting.reports.pdf_renderer import render_pdf

def run_mitigation():
    run = AnalysisRun.objects.filter(pk=14).first()
    if not run:
        print("AnalysisRun #14 not found!")
        return

    print(f"Found AnalysisRun #{run.pk} (session_id={run.session_id}, status={run.status})")
    plan = MitigationPlan.objects.filter(run=run).first()
    if not plan:
        plan = MitigationPlan.objects.create(
            run=run,
            mode=run.mode,
            session_id=run.session_id,
            status=MitigationPlan.Status.PENDING,
            progress=0,
        )
    else:
        plan.status = MitigationPlan.Status.PENDING
        plan.error = ""
        plan.save()

    print(f"Generating Mitigation Plan #{plan.pk} for Run #{run.pk}...")
    finished_plan = generate_plan(plan.pk, mode=run.mode)
    
    doc = finished_plan.document
    s = doc.get("summary", {})
    
    print("\n==================================================")
    print("           ACTUAL MITIGATION PLAN METRICS          ")
    print("==================================================")
    print(f"Canonical Assets Analyzed: {s.get('assets')}")
    print(f"Wave 1 (0-3 mo, Urgent/Classical Weak/HNDL): {s.get('wave1')}")
    print(f"Wave 2 (3-12 mo, Post-Quantum Shor Migration): {s.get('wave2')}")
    print(f"Wave 3 (12-24 mo, Symmetric Hardening & Governance): {s.get('wave3')}")
    print(f"Total Wave Work Items: {s.get('wave1', 0) + s.get('wave2', 0) + s.get('wave3', 0)}")
    print(f"Remediation Work-Items Count: {s.get('actions_count', s.get('assets'))}")
    print(f"Deduplicated Tasks: {s.get('deduplicated_tasks')}")
    print(f"Effort Range: LOW={s.get('effort_low_quarters')} quarters | HIGH={s.get('effort_high_quarters')} quarters")
    
    print("\n--- Work Items Breakdown ---")
    for r in doc.get("rows", []):
        algo = r.get("algorithm")
        prio = r.get("migration_priority")
        wave = r.get("migration_wave")
        service = r.get("service")
        rep = (r.get("migration_impact") or {}).get("replacement")
        print(f"  Wave {wave} | Prio: {prio:<6} | {algo:<10} | Service: {service:<25} | Replacement: {rep}")

    # Report build and invariants
    rep = build_report(sid=run.session_id)
    invariants = _evaluate_invariants(rep["data"])
    
    print("\n==================================================")
    print("              ALL INVARIANT RESULTS               ")
    print("==================================================")
    for inv in invariants:
        status = "PASS" if inv["passed"] else "FAIL"
        print(f"  [{status}] {inv['name']}: {inv['detail']}")
    
    all_passed = all(inv["passed"] for inv in invariants)
    print(f"\nAll Invariants Passed: {all_passed} ({len(invariants)}/10)")

    # Render PDF
    html_content = rep["html"]
    pdf_filename = rep["filename"]
    pdf_path = os.path.join(os.path.dirname(__file__), pdf_filename)
    print(f"\nRendering regenerated PDF: {pdf_filename}...")
    pdf_bytes = render_pdf(html_content)
    with open(pdf_path, "wb") as f:
        f.write(pdf_bytes)
    print(f"PDF successfully generated at: {pdf_path} (size: {len(pdf_bytes)} bytes)")

if __name__ == "__main__":
    run_mitigation()
