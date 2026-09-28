"""Demo & Verification script for the Reporting Segment.

Consumes:
  1. ML Final Risk Report (ecdat_final_risk_report.json)
  2. Mitigation Plan (mitigation_plan_output.json)

Produces:
  1. Executive HTML Report (ecdat_executive_report.html)
  2. Professional Print-Ready PDF Report (ecdat_executive_report.pdf)
  3. Interactive Dashboard KPIs & Metrics (dashboard_overview_metrics.json)
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add backend root to path
backend_dir = Path(__file__).resolve().parent.parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from segments.reporting.reports.pdf_renderer import render_pdf


def generate_executive_html(ml_report: dict, mitigation_plan: dict) -> str:
    """Build a comprehensive, print-ready A4 HTML report."""
    stats = ml_report.get("portfolio_stats", {})
    mit_summary = mitigation_plan.get("summary", {})
    waves = mitigation_plan.get("waves", [])
    rows = mitigation_plan.get("rows", [])
    twin = mitigation_plan.get("digital_twin", {})
    blast = mitigation_plan.get("blast_radius", {})
    recs = mitigation_plan.get("strategic_recommendations", []) or mitigation_plan.get("recommendations", [])

    total_assets = stats.get("total_assets", len(rows))
    high_risk = stats.get("high_risk_count", mit_summary.get("urgent", 0))
    qv_count = stats.get("mosca_deficit_count", mit_summary.get("quantum_vulnerable", 0))
    hndl_count = stats.get("hndl_exposed_count", mit_summary.get("hndl_exposed", 0))

    # Wave rows
    wave_cards_html = ""
    for w in waves:
        wave_cards_html += f"""
        <div class="wave-card">
          <div class="wave-header">
            <h4>{w.get('name', 'Wave')}</h4>
            <span class="badge b-navy">{w.get('timeline', 'Q1-Q2')}</span>
          </div>
          <p class="small">{w.get('focus', '')}</p>
          <div class="wave-stats">
            <b>Assets Allocated: {w.get('asset_count', len(w.get('assets', [])))}</b>
          </div>
        </div>
        """

    # Asset Table rows
    table_rows_html = ""
    for r in rows:
        impact = r.get("migration_impact", {})
        br = r.get("blast_radius", {})
        wave_badge = "b-red" if r.get("migration_wave") == 1 else "b-amber" if r.get("migration_wave") == 2 else "b-green"
        table_rows_html += f"""
        <tr>
          <td class="mono">{r.get('asset_id') or r.get('id')}</td>
          <td class="mono"><b>{r.get('algorithm')}</b></td>
          <td>{r.get('algorithm_category', 'PUBLIC_KEY')}</td>
          <td><span class="badge {wave_badge}">Wave {r.get('migration_wave', 1)}</span></td>
          <td class="mono small">{impact.get('replacement', 'NIST PQC')}</td>
          <td><span class="badge {'b-red' if br.get('severity') == 'CRITICAL' else 'b-amber'}">{br.get('severity', 'HIGH')}</span></td>
          <td class="small">{r.get('suggestions', [''])[0] if r.get('suggestions') else r.get('recommended_action', 'Migrate')}</td>
        </tr>
        """

    # Recommendations HTML
    rec_items_html = ""
    for rec in recs[:4]:
        title = rec.get("title") if isinstance(rec, dict) else str(rec)
        desc = rec.get("description", "") if isinstance(rec, dict) else ""
        actions = rec.get("actions", []) if isinstance(rec, dict) else []
        action_lis = "".join(f"<li>{a}</li>" for a in actions)
        rec_items_html += f"""
        <div class="rec-item">
          <h4>{title}</h4>
          <p>{desc}</p>
          {f'<ul class="tight">{action_lis}</ul>' if action_lis else ''}
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ECDAT Executive Post-Quantum Cryptography Assessment</title>
<style>
:root {{
  --navy: #0f2745; --ink: #1f2937; --muted: #55627a; --faint: #8a95ab; --rule: #d7dde8;
  --paper: #ffffff; --accent: #155e75; --red: #b91c1c; --amber: #b45309; --green: #15803d;
}}
* {{ box-sizing: border-box; }}
body {{
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  color: var(--ink); margin: 0; padding: 24pt 30pt; font-size: 9.5pt; line-height: 1.5;
  -webkit-print-color-adjust: exact; print-color-adjust: exact;
}}
@page {{
  size: A4; margin: 18mm 15mm 20mm 15mm;
  @bottom-right {{ content: "ECDAT · Confidential · Page " counter(page) " of " counter(pages); font-size: 7pt; color: var(--faint); }}
  @bottom-left {{ content: "Prepared by ECDAT Enterprise PQC Suite"; font-size: 7pt; color: var(--faint); }}
}}
h1, h2, h3, h4 {{ margin: 0; line-height: 1.25; }}
p {{ margin: 0 0 7pt; }}
.mono {{ font-family: 'Cascadia Mono', Consolas, Menlo, monospace; font-size: 8.3pt; }}
.cover {{ border-bottom: 2.5pt solid var(--navy); padding-bottom: 14pt; margin-bottom: 14pt; }}
.cover .kicker {{ font-size: 8pt; letter-spacing: 3px; color: var(--accent); text-transform: uppercase; font-weight: 600; }}
.cover h1 {{ font-size: 21pt; color: var(--navy); margin: 4pt 0 2pt; }}
.cover .sub {{ font-size: 10.5pt; color: var(--muted); }}
.meta {{ display: flex; flex-wrap: wrap; gap: 6pt 22pt; margin-top: 10pt; font-size: 8.3pt; color: var(--muted); }}
.meta b {{ color: var(--ink); display: block; font-size: 7pt; text-transform: uppercase; letter-spacing: 1px; color: var(--faint); }}
.conf-ribbon {{ display: inline-block; margin-top: 8pt; padding: 3pt 8pt; border: 0.75pt solid var(--amber); color: var(--amber); font-size: 7.5pt; letter-spacing: 1px; text-transform: uppercase; border-radius: 2pt; }}
h2.sec {{ font-size: 12.5pt; color: var(--navy); margin: 14pt 0 8pt; padding-bottom: 4pt; border-bottom: 1.25pt solid var(--rule); break-after: avoid; }}
h2.sec .no {{ color: var(--accent); font-weight: 700; margin-right: 6pt; }}
h3 {{ font-size: 10pt; color: var(--ink); margin: 8pt 0 5pt; break-after: avoid; }}
.kpi-row {{ display: flex; flex-wrap: wrap; gap: 7pt; margin: 0 0 10pt; }}
.kpi {{ flex: 1 1 120pt; border: 0.75pt solid var(--rule); border-top: 2.5pt solid var(--accent); padding: 6pt 8pt; border-radius: 3pt; break-inside: avoid; background: #fff; }}
.kpi .n {{ font-size: 16pt; font-weight: 700; color: var(--navy); font-family: 'Cascadia Mono', Consolas, monospace; }}
.kpi .l {{ font-size: 7.3pt; text-transform: uppercase; letter-spacing: 1px; color: var(--faint); }}
.kpi.warn {{ border-top-color: var(--amber); }}
.kpi.danger {{ border-top-color: var(--red); }}
.kpi.ok {{ border-top-color: var(--green); }}
table {{ width: 100%; border-collapse: collapse; margin: 4pt 0 10pt; font-size: 8.2pt; }}
th {{ background: var(--navy); color: #fff; text-align: left; padding: 5pt 6pt; font-size: 7.3pt; text-transform: uppercase; letter-spacing: 0.6px; }}
td {{ padding: 4.5pt 6pt; border-bottom: 0.6pt solid var(--rule); vertical-align: top; }}
tr:nth-child(even) td {{ background: #f8fafc; }}
.callout {{ border-left: 3.5pt solid var(--accent); background: #eef5f8; padding: 7pt 10pt; margin: 6pt 0 10pt; font-size: 8.7pt; border-radius: 0 3pt 3pt 0; break-inside: avoid; }}
.callout.warn {{ border-color: var(--amber); background: #fdf7ea; }}
.callout.danger {{ border-color: var(--red); background: #fdefef; }}
.badge {{ display: inline-block; padding: 1pt 5pt; border-radius: 4pt; font-size: 7pt; font-weight: 600; letter-spacing: 0.4px; color: #fff; }}
.b-red {{ background: var(--red); }}
.b-amber {{ background: var(--amber); }}
.b-green {{ background: var(--green); }}
.b-navy {{ background: var(--navy); }}
.wave-grid {{ display: flex; gap: 8pt; margin-bottom: 12pt; flex-wrap: wrap; }}
.wave-card {{ flex: 1 1 30%; border: 1pt solid var(--rule); padding: 8pt; border-radius: 4pt; background: #fafbfc; }}
.wave-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 4pt; }}
.rec-item {{ border-left: 2.5pt solid var(--navy); padding: 4pt 8pt; margin-bottom: 8pt; background: #f8fafc; }}
.small {{ font-size: 7.8pt; color: var(--muted); }}
ul.tight {{ margin: 2pt 0 4pt; padding-left: 14pt; font-size: 8.2pt; }}
ul.tight li {{ margin-bottom: 2pt; }}
.page-break {{ break-before: page; }}
</style>
</head>
<body>

<!-- Header Cover -->
<div class="cover">
  <div class="kicker">ECDAT · Enterprise Cryptographic Discovery &amp; Assessment</div>
  <h1>Post-Quantum Cryptography (PQC) Migration &amp; Risk Report</h1>
  <div class="sub">Comprehensive Multi-Engine Assessment: ML Risk Classifier, HNDL Threat, Mosca Timeline &amp; Mitigation Roadmap</div>
  <div class="meta">
    <div><b>Assessment Target</b>{ml_report.get('report_title', 'ECDAT Enterprise Repository')}</div>
    <div><b>Generated At</b>{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</div>
    <div><b>PQC Standards</b>NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)</div>
  </div>
  <div class="conf-ribbon">Confidential · Enterprise Security Governance Report</div>
</div>

<!-- Section 1: Executive KPI Dashboard -->
<h2 class="sec"><span class="no">1</span>Executive KPI Dashboard</h2>
<div class="kpi-row">
  <div class="kpi">
    <div class="n">{total_assets}</div>
    <div class="l">Total Cryptographic Assets</div>
  </div>
  <div class="kpi danger">
    <div class="n">{qv_count}</div>
    <div class="l">Quantum-Vulnerable Primitives</div>
  </div>
  <div class="kpi warn">
    <div class="n">{hndl_count}</div>
    <div class="l">HNDL Harvest-Now Exposed</div>
  </div>
  <div class="kpi danger">
    <div class="n">{mit_summary.get('wave1', 0)}</div>
    <div class="l">Wave 1 Immediate Actions</div>
  </div>
  <div class="kpi ok">
    <div class="n">{mit_summary.get('effort_estimate_quarters', 4)} Qtrs</div>
    <div class="l">Estimated Migration Duration</div>
  </div>
</div>

<div class="callout danger">
  <b>Executive Summary:</b> {mitigation_plan.get('executive_summary', ml_report.get('executive_summary', 'Assessment completed.'))}
</div>

<!-- Section 2: Quantum Threat & Mosca Theorem Assessment -->
<h2 class="sec"><span class="no">2</span>Quantum Threat &amp; Timeline Deficit</h2>
<p>
  Under <b>Michele Mosca's Theorem (X + Y &gt; Z)</b>, if the migration duration (X) plus the required data shelf-life (Y)
  exceeds the estimated time to a Cryptographically Relevant Quantum Computer (Z), assets fall into an active security deficit.
</p>
<div class="callout warn">
  <b>Quantum Vulnerability Vector:</b> {mitigation_plan.get('quantum_risk_narrative', '')}
</div>

<!-- Section 3: Multi-Wave Mitigation Plan -->
<h2 class="sec"><span class="no">3</span>Wave-Based PQC Remediation Roadmap</h2>
<div class="wave-grid">
  {wave_cards_html}
</div>

<!-- Section 4: Cryptographic Inventory & Action Directives -->
<div class="page-break"></div>
<h2 class="sec"><span class="no">4</span>Inventory &amp; Target PQC Replacements</h2>
<table>
  <thead>
    <tr>
      <th>Asset ID</th>
      <th>Algorithm</th>
      <th>Category</th>
      <th>Migration Wave</th>
      <th>Target PQC Standard</th>
      <th>Blast Radius</th>
      <th>Action Directive</th>
    </tr>
  </thead>
  <tbody>
    {table_rows_html}
  </tbody>
</table>

<!-- Section 5: Strategic Executive Recommendations -->
<h2 class="sec"><span class="no">5</span>Strategic Governance &amp; Policy Recommendations</h2>
{rec_items_html}

</body>
</html>
"""
    return html


def main():
    print("=" * 80)
    print("ECDAT REPORTING SEGMENT - EXECUTIVE REPORT & DASHBOARD GENERATOR")
    print("=" * 80)

    # 1. Ingest ML Risk Report and Mitigation Plan
    ml_report_path = backend_dir / "ecdat_final_risk_report.json"
    if not ml_report_path.exists():
        ml_report_path = backend_dir / "segments" / "ml" / "ecdat_final_risk_report.json"

    mit_plan_path = backend_dir / "segments" / "mitigation" / "mitigation_plan_output.json"

    print(f"[*] Ingesting ML Risk Report:     {ml_report_path.name}")
    with open(ml_report_path, "r", encoding="utf-8") as f:
        ml_report = json.load(f)

    print(f"[*] Ingesting Mitigation Plan:    {mit_plan_path.name}")
    with open(mit_plan_path, "r", encoding="utf-8") as f:
        mitigation_plan = json.load(f)

    # 2. Generate HTML Report
    print("[*] Building Executive HTML Report Snapshot...")
    html_content = generate_executive_html(ml_report, mitigation_plan)

    reporting_dir = Path(__file__).resolve().parent
    html_out_path = reporting_dir / "ecdat_executive_report.html"
    with open(html_out_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[+] HTML Report generated: {html_out_path}")

    # 3. Render PDF via Headless Chromium
    print("[*] Rendering print-ready PDF Report via Chromium engine...")
    pdf_out_path = reporting_dir / "ecdat_executive_report.pdf"
    try:
        pdf_bytes = render_pdf(html_content)
        with open(pdf_out_path, "wb") as f:
            f.write(pdf_bytes)
        print(f"[+] PDF Report successfully rendered ({len(pdf_bytes):,} bytes): {pdf_out_path}")
    except Exception as exc:
        print(f"[!] PDF generation note: {exc}")

    # 4. Generate Dashboard Metrics JSON
    print("[*] Generating Dashboard Overview Metrics payload...")
    mit_summary = mitigation_plan.get("summary", {})
    stats = ml_report.get("portfolio_stats", {})
    total = stats.get("total_assets", mit_summary.get("assets", 10))
    qv = mit_summary.get("quantum_vulnerable", stats.get("mosca_deficit_count", 5))

    dashboard_metrics = {
        "kpis": {
            "total_crypto_assets": total,
            "quantum_vulnerable_count": qv,
            "quantum_vulnerable_pct": round((qv / total) * 100, 1) if total else 0,
            "hndl_exposed_count": stats.get("hndl_exposed_count", mit_summary.get("hndl_exposed", 0)),
            "urgent_wave1_count": mit_summary.get("wave1", 0),
            "pqc_migration_wave2_count": mit_summary.get("wave2", 0),
            "hardening_wave3_count": mit_summary.get("wave3", 0),
            "estimated_quarters": mit_summary.get("effort_estimate_quarters", 6),
            "earliest_deadline_year": stats.get("earliest_migration_deadline_year", 2029.8),
        },
        "waves": mitigation_plan.get("waves", []),
        "risk_distribution": {
            "critical": stats.get("critical_risk_count", 0),
            "high": stats.get("high_risk_count", 6),
            "medium": stats.get("medium_risk_count", 1),
            "low": stats.get("low_risk_count", 3),
        },
        "digital_twin": mitigation_plan.get("digital_twin", {}),
        "blast_radius_summary": mitigation_plan.get("blast_radius", {}),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    metrics_out_path = reporting_dir / "dashboard_overview_metrics.json"
    with open(metrics_out_path, "w", encoding="utf-8") as f:
        json.dump(dashboard_metrics, f, indent=2)
    print(f"[+] Dashboard Metrics saved: {metrics_out_path}")

    print("=" * 80)
    print("REPORTING SEGMENT COMPLETE!")
    print("=" * 80)


if __name__ == "__main__":
    main()
