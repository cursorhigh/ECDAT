import os, sys, django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from segments.scraping.discovery.models import RawFinding, NormalizedFinding, CryptoAsset, ScanJob
from segments.ml.analysis.models import AnalysisRun, AssetAssessment

print('=== SCAN JOBS ===')
for sj in ScanJob.objects.order_by('-id')[:3]:
    print(f'ScanJob {sj.id}: target={sj.target}, status={sj.status}, findings_count={sj.findings_count}')

print('\n=== LATEST RUNS ===')
for r in AnalysisRun.objects.order_by('-id')[:3]:
    stats = (r.executive_summary or {}).get("stats", {})
    target_str = getattr(r.scan_job, "target", "") if r.scan_job else ""
    print(f'Run ID: {r.id}, Target: {target_str}, Status: {r.status}, Stats: {stats}')
    rows = (r.executive_summary or {}).get("rows", [])
    print(f'  Total rows in exec_summary: {len(rows)}')
    for row in rows[:5]:
        print(f'    Row: {row}')

print('\n=== LATEST RAW FINDINGS ===')
for rf in RawFinding.objects.order_by('-id')[:5]:
    print(f'RawFinding {rf.id}: algo={rf.algorithm}, raw_json={rf.raw_json}')

print('\n=== LATEST NORMALIZED FINDINGS ===')
for nf in NormalizedFinding.objects.order_by('-id')[:5]:
    print(f'NormFinding {nf.id}: algo={nf.algorithm}, evidence={nf.evidence}')

print('\n=== LATEST CRYPTO ASSETS ===')
for ca in CryptoAsset.objects.order_by('-id')[:5]:
    print(f'CryptoAsset {ca.id}: name={ca.name}, algo={ca.algorithm}, env={ca.environment}, loc={ca.location}')
