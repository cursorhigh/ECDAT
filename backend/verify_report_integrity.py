import os
import django

os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings'
django.setup()

from segments.reporting.reports.report_builder import build_report, _evaluate_invariants

def verify():
    rep = build_report()
    data = rep["data"]
    html = rep["html"]
    
    print("=== ECDAT REPORT DATA VERIFICATION ===")
    print("Total Scans:", data["kpis"]["scans"])
    print("Raw Findings:", data["kpis"]["raw_findings"])
    print("Normalized Findings:", data["kpis"]["normalized_findings"])
    print("Canonical Assets:", data["kpis"]["assets"])
    print("Risk Breakdown:", data["kpis"]["risk_counts"])
    
    print("\n=== SECTION HEADERS ===")
    for line in html.splitlines():
        if '<h2' in line:
            print(" ", line.strip())
            
    print("\n=== INVARIANTS EVALUATION ===")
    invariants = _evaluate_invariants(data)
    for inv in invariants:
        status = "PASS" if inv["passed"] else "FAIL"
        print(f"  [{status}] {inv['name']}: {inv['detail']}")
        
    all_passed = all(inv["passed"] for inv in invariants)
    print("\nAll Invariants Passed:", all_passed)

if __name__ == "__main__":
    verify()
