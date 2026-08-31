"""Enterprise full-pipeline report generator.

Builds a self-contained HTML document (inline CSS, print-ready A4) covering the
whole ECDAT workflow for the current scope:

    Discovery scans -> intake -> normalization -> inventory & quantum risk
    -> correlation graph -> analysis runs -> mitigation plan.

The document is also the source for PDF rendering (see ``pdf_renderer``). The
PDF is never persisted server-side — it is handed to the front-end as base64
and the browser asks the user to save it.
"""

from __future__ import annotations

from datetime import datetime

from django.utils import html as _html

APPLICATION_NAME = "ECDAT"
REPORT_SUBTITLE = "Cryptographic Post-Quantum Readiness Assessment"

# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

_PAGE_CSS = """
:root{--navy:#0f2745;--ink:#1f2937;--muted:#55627a;--faint:#8a95ab;--rule:#d7dde8;
--paper:#ffffff;--accent:#155e75;--red:#b91c1c;--amber:#b45309;--green:#15803d;}
*{box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;color:var(--ink);
margin:0;padding:24pt 30pt;font-size:9.5pt;line-height:1.5;-webkit-print-color-adjust:exact;print-color-adjust:exact}
@page{size:A4;margin:18mm 15mm 20mm 15mm;
@bottom-right{content:"ECDAT \\00a0·\\00a0 Confidential \\00a0·\\00a0 Page " counter(page) " of " counter(pages);
font-size:7pt;color:var(--faint);font-family:'Segoe UI',sans-serif;}
@bottom-left{content:"Prepared for internal PQC program";font-size:7pt;color:var(--faint);}}
h1,h2,h3,h4{margin:0;line-height:1.25}
p{margin:0 0 7pt}
.mono{font-family:Cascadia Mono,Consolas,Menlo,monospace;font-size:8.3pt}
.cover{border-bottom:2.5pt solid var(--navy);padding-bottom:14pt;margin-bottom:14pt}
.cover .kicker{font-size:8pt;letter-spacing:3px;color:var(--accent);text-transform:uppercase;font-weight:600}
.cover h1{font-size:21pt;color:var(--navy);margin:4pt 0 2pt}
.cover .sub{font-size:10.5pt;color:var(--muted)}
.meta{display:flex;flex-wrap:wrap;gap:6pt 22pt;margin-top:10pt;font-size:8.3pt;color:var(--muted)}
.meta b{color:var(--ink);display:block;font-size:7pt;text-transform:uppercase;letter-spacing:1px;color:var(--faint)}
.conf-ribbon{display:inline-block;margin-top:8pt;padding:3pt 8pt;border:0.75pt solid var(--amber);
color:var(--amber);font-size:7.5pt;letter-spacing:1px;text-transform:uppercase;border-radius:2pt}
h2.sec{font-size:12.5pt;color:var(--navy);margin:0 0 8pt;padding-bottom:4pt;border-bottom:1.25pt solid var(--rule);
break-after:avoid}
h2.sec .no{color:var(--accent);font-weight:700;margin-right:6pt}
h3{font-size:10pt;color:var(--ink);margin:0 0 5pt;break-after:avoid}
.kpi-row{display:flex;flex-wrap:wrap;gap:7pt;margin:0 0 10pt}
.kpi{flex:1 1 120pt;border:0.75pt solid var(--rule);border-top:2pt solid var(--accent);
padding:6pt 8pt;border-radius:3pt;break-inside:avoid}
.kpi .n{font-size:15pt;font-weight:700;color:var(--navy);font-family:Cascadia Mono,Consolas,monospace}
.kpi .l{font-size:7.3pt;text-transform:uppercase;letter-spacing:1px;color:var(--faint)}
.kpi.neutral{border-top-color:var(--accent)}.kpi.warn{border-top-color:var(--amber)}
.kpi.danger{border-top-color:var(--red)}.kpi.ok{border-top-color:var(--green)}
table{width:100%;border-collapse:collapse;margin:2pt 0 10pt;font-size:8.2pt}
th{background:var(--navy);color:#fff;text-align:left;padding:4pt 6pt;font-size:7.3pt;
text-transform:uppercase;letter-spacing:0.6px}
td{padding:3.5pt 6pt;border-bottom:0.6pt solid var(--rule);vertical-align:top}
tr:nth-child(even) td{background:#f5f7fb}
td.num,th.num{text-align:right}
.section{margin:0 0 6pt;break-inside:avoid}
.note{font-size:8pt;color:var(--muted);font-style:italic;margin:2pt 0 8pt}
.callout{border-left:3pt solid var(--accent);background:#eef5f8;padding:6pt 9pt;margin:0 0 10pt;
font-size:8.7pt;break-inside:avoid}
.callout.warn{border-color:var(--amber);background:#fdf7ea}
.callout.danger{border-color:var(--red);background:#fdefef}
.codebox{background:#0b1522;color:#d8e3f2;font-family:Cascadia Mono,Consolas,monospace;font-size:7.6pt;
padding:6pt 8pt;border-radius:3pt;margin:2pt 0 10pt;white-space:pre-wrap;break-inside:avoid}
.badge{display:inline-block;padding:0.5pt 5pt;border-radius:8pt;font-size:7pt;font-weight:600;
letter-spacing:0.4px;color:#fff;line-height:1.5}
.b-red{background:var(--red)}.b-amber{background:var(--amber)}.b-green{background:var(--green)}
.b-gray{background:#6b7280}.b-navy{background:var(--navy)}
.grid2{display:flex;gap:9pt;flex-wrap:wrap}
.grid2>div{flex:1 1 45%}
.page-break{break-before:page}
.small{font-size:7.6pt;color:var(--muted)}
ul.tight{margin:2pt 0 8pt;padding-left:14pt}
ul.tight li{margin:0 0 3pt}
"""


# ---------------------------------------------------------------------------
# Escaping helpers
# ---------------------------------------------------------------------------

def _esc(value):
    """HTML-escape a value; None -> empty string."""
    if value is None:
        return ""
    return _html.escape(str(value))


def _fmt_dt(value):
    if not value:
        return "—"
    return value


def _pct(part: int, total: int) -> int:
    return round(100 * part / total) if total else 0


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------

def _scoped(db):
    from core.modes import active_db
    from core.sessions import thread_session_id

    sid = thread_session_id() or None
    return sid, db or active_db()


def _risk_of(asset):
    from dashboard.views import _asset_risk, _pqc_replacement, _priority_score

    key, label, _badge = _asset_risk(asset)
    return {
        "risk_key": key,
        "label": label,
        "priority": asset.family in ("rsa", "dsa", "dh", "ecc", "hash"),
        "score": _priority_score(asset, key),
        "replacement": _pqc_replacement(asset),
    }


def collect(sid=None, db=None):
    """Gather every pipeline artifact for the current scope into one dict."""
    from django.db.models import Count, Q

    from analysis.models import AnalysisRun
    from core.sessions import scope
    from discovery.models import AssetRelation, CryptoAsset, NormalizedFinding, RawFinding, ScanJob
    from mitigation.models import MitigationPlan

    sid, db = _scoped(db)
    _s = lambda qs: scope(qs, sid)

    now = datetime.now()
    ws = None
    if sid:
        from core.models import WorkSession

        ws = WorkSession.objects.using(db).filter(pk=sid).first()
    scope_label = f"Workspace “{ws.name}”" if ws else "All data (no workspace filter)"

    scans = list(_s(ScanJob.objects.all()).order_by("-created_at")[:80])
    raw_qs = _s(RawFinding.objects.all())
    norm_qs = _s(NormalizedFinding.objects.all())
    assets = list(_s(CryptoAsset.objects.all()).order_by("name"))

    asset_rows = []
    risk_counts = {"vulnerable": 0, "weak": 0, "moderate": 0, "pqc": 0, "unknown": 0}
    quantum_vuln = 0
    for a in assets:
        r = _risk_of(a)
        risk_counts[r["risk_key"]] += 1
        if r["risk_key"] in ("vulnerable", "weak"):
            quantum_vuln += 1
        asset_rows.append(
            {
                "id": a.pk,
                "name": a.name,
                "family": a.get_family_display(),
                "algorithm": a.algorithm,
                "key_size": a.key_size,
                "curve": a.curve,
                "source_type": a.get_source_type_display(),
                "location": a.location,
                "risk_key": r["risk_key"],
                "risk_label": r["label"],
                "score": r["score"],
                "replacement": r["replacement"],
            }
        )
    asset_rows.sort(key=lambda x: (-x["score"], x["risk_key"] not in ("vulnerable", "weak"), x["name"]))
    asset_rows = asset_rows[:500]
    total_asset_rows = len(assets)

    raw_count = raw_qs.count()
    norm_count = norm_qs.count()
    relation_count = AssetRelation.objects.using(db).all()
    if sid:
        relation_count = relation_count.filter(Q(session_id=sid))
    relation_count = relation_count.count()

    families = {
        f["family"]: f["c"]
        for f in norm_qs.values("family").annotate(c=Count("id"))
    }
    family_rows = [
        {"family": k, "label": dict(NormalizedFinding.AlgorithmFamily.choices).get(k, k), "count": v}
        for k, v in sorted(families.items(), key=lambda kv: (-kv[1], kv[0]))
    ]

    runs = list(_s(AnalysisRun.objects.all()).order_by("-created_at")[:40])
    run_rows = []
    latest_completed = None
    for run in runs:
        es = run.executive_summary or {}
        stats = es.get("stats") or {}
        rows = es.get("rows") or []
        run_rows.append(
            {
                "id": run.pk,
                "target": run.scan_job.target if run.scan_job else "—",
                "status": run.get_status_display(),
                "status_key": run.status,
                "progress": run.progress,
                "created": run.created_at,
                "stats": stats,
                "rows": rows,
            }
        )
        if run.status == AnalysisRun.Status.COMPLETED and latest_completed is None:
            latest_completed = run

    plan = None
    plan_rows = None
    if latest_completed is not None:
        plan = (
            MitigationPlan.objects.using(db)
            .filter(run=latest_completed)
            .order_by("-created_at")
            .first()
        )
    if plan is None and any(r["status_key"] == AnalysisRun.Status.COMPLETED for r in run_rows):
        plan = _s(MitigationPlan.objects.all()).order_by("-created_at").first()

    mitigation = None
    if plan is not None and plan.status == MitigationPlan.Status.COMPLETE:
        doc = plan.document or {}
        summary = doc.get("summary") or {}
        blast = doc.get("blast_radius") or {}
        twin = doc.get("digital_twin") or {}
        quantum = doc.get("quantum_risk") or {}
        mitigation = {
            "plan_id": plan.pk,
            "run_id": plan.run_id,
            "generated_at": plan.generated_at,
            "app": doc.get("application") or "",
            "enhanced": bool((doc.get("ai_context") or {}).get("enhanced")),
            "model_used": (doc.get("ai_context") or {}).get("model_used"),
            "executive_summary": doc.get("executive_summary") or "",
            "quantum_risk_narrative": doc.get("quantum_risk_narrative") or "",
            "qv_assets": list(quantum.get("post_quantum_vulnerable") or []),
            "summary": summary,
            "blast": blast,
            "twin": twin,
            "waves": doc.get("waves") or [],
            "strategic": doc.get("strategic_recommendations") or [],
            "recommendations": doc.get("recommendations") or [],
            "rows": doc.get("rows") or [],
        }

    return {
        "meta": {
            "app": APPLICATION_NAME,
            "subtitle": REPORT_SUBTITLE,
            "generated_at": now.strftime("%Y-%m-%d %H:%M"),
            "generated_iso": now.isoformat(timespec="seconds"),
            "scope_label": scope_label,
            "session_name": ws.name if ws else "All data",
        },
        "kpis": {
            "scans": len(scans),
            "raw_findings": raw_count,
            "normalized_findings": norm_count,
            "assets": total_asset_rows,
            "quantum_vulnerable": quantum_vuln,
            "quantum_pct": _pct(quantum_vuln, total_asset_rows),
            "families": len(family_rows),
            "relations": relation_count,
            "completed_runs": sum(1 for r in run_rows if r["status_key"] == AnalysisRun.Status.COMPLETED),
            "mitigation": 1 if mitigation else 0,
            "risk_counts": risk_counts,
        },
        "scans": [
            {
                "id": s.pk,
                "target": s.target,
                "source_type": s.get_source_type_display(),
                "status": s.get_status_display(),
                "created": s.created_at,
            }
            for s in scans
        ],
        "family_rows": family_rows,
        "assets": asset_rows,
        "asset_count": total_asset_rows,
        "relation_count": relation_count,
        "runs": run_rows,
        "mitigation": mitigation,
        "scope_id": sid,
    }


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _kpi_row(kpis: dict) -> str:
    pct = kpis["quantum_pct"]
    badge_cls = "ok" if pct < 15 else ("warn" if pct < 40 else "danger")
    cards = [
        ("neutral", kpis["scans"], "scans"),
        ("neutral", kpis["raw_findings"], "raw findings"),
        ("neutral", kpis["normalized_findings"], "normalized"),
        ("neutral", kpis["assets"], "assets / artefacts"),
        (badge_cls, f"{kpis['quantum_vulnerable']} ({pct}%)", "quantum-exposed"),
        ("warn", kpis["relations"], "graph relations"),
        ("ok", kpis["completed_runs"], "completed analyses"),
        ("neutral", kpis["mitigation"], "mitigation plans"),
    ]
    html = ['<div class="kpi-row">']
    for cls, n, label in cards:
        html.append(f'<div class="kpi {cls}"><div class="n">{_esc(n)}</div><div class="l">{_esc(label)}</div></div>')
    html.append("</div>")
    return "\n".join(html)


def _badge(label, color):
    return f'<span class="badge b-{color}">{_esc(label)}</span>'


def _severity_badge(label):
    color = {
        "CRITICAL": "red",
        "HIGH": "red",
        "URGENT": "red",
        "MEDIUM": "amber",
        "LOW": "green",
        "PQC-READY": "green",
        "MODERATE": "amber",
    }.get(str(label or "").upper(), "gray")
    return _badge(label or "—", color)


def _risk_badge(key, label):
    color = {"vulnerable": "red", "weak": "red", "moderate": "amber", "pqc": "green", "unknown": "gray"}[key]
    return _badge(label, color)


_SECTIONS = {"scan": "Discovery scan", "intake": "Raw intake", "norm": "Normalization"}


def _sec_cover(meta, kpis) -> str:
    kv = []
    kv.append(f"<div><b>Prepared</b>{_esc(meta['generated_at'])}</div>")
    kv.append(f"<div><b>Scope</b>{_esc(meta['scope_label'])}</div>")
    kv.append(f"<div><b>Coverage</b>{kpis['scans']} scans · {kpis['assets']} assets</div>")
    kv.append(f"<div><b>Version</b>ECDAT · PQC readiness</div>")
    return f"""
<div class="cover">
  <div class="kicker">{_esc(meta['app'])} · {_esc(meta['subtitle'])}</div>
  <h1>Full Pipeline Report</h1>
  <div class="sub">Discovery · Inventory · Correlation · Analysis · Mitigation</div>
  <div class="meta">{''.join(kv)}</div>
  <div class="conf-ribbon">Confidential — internal use only</div>
</div>
"""


def _sec_exec(kpis, mitigation) -> str:
    rc = kpis["risk_counts"]
    pct = kpis["quantum_pct"]
    rows = []
    rows.append(
        f"This assessment covered <b>{kpis['scans']}</b> discovery scan(s), ingesting "
        f"<b>{kpis['raw_findings']}</b> raw finding(s) which normalized into "
        f"<b>{kpis['normalized_findings']}</b> canonical record(s) and <b>{kpis['assets']}</b> "
        f"crypto asset(s) across <b>{kpis['families']}</b> algorithm families."
    )
    rows.append(
        f"Of the estate, <b>{kpis['quantum_vulnerable']} assets ({pct}%)</b> are classified as "
        f"post-quantum vulnerable — classical asymmetric primitives (RSA/DSA/DH/ECC) break under "
        f"Shor's algorithm, and weak hashes (MD5/SHA-1) are already cryptographically broken."
    )
    if mitigation:
        s = mitigation["summary"]
        rows.append(
            f"A mitigation plan is available (plan #{mitigation['plan_id']}, run #{mitigation['run_id']}) "
            f"that sequences the estate into migration waves: <b>{s.get('wave1', 0)}</b> assets in Wave 1, "
            f"<b>{s.get('wave2', 0)}</b> in Wave 2, <b>{s.get('wave3', 0)}</b> in Wave 3. "
            f"<b>{s.get('urgent', 0)}</b> asset(s) are URGENT; "
            f"<b>{s.get('quantum_vulnerable', 0)}</b> are quantum-vulnerable and "
            f"<b>{s.get('hndl_exposed', 0)}</b> are exposed to harvest-now-decrypt-later (HNDL) threats. "
            f"Estimated effort is roughly <b>{s.get('effort_estimate_quarters', 0)}</b> engineering quarter(s)."
        )
    else:
        rows.append(
            "Run the mitigation stage to obtain an AI-optimized, wave-sequenced remediation plan "
            "with blast radius and migration impact for every exposed asset."
        )
    body = "\n".join(f"<p>{r}</p>" for r in rows)
    return f"""
<div class="section">
  <h2 class="sec"><span class="no">1</span>Executive Summary</h2>
  {_kpi_row(kpis)}
  {body}
  <div class="callout">
    <b>Bottom line:</b> {pct}% of the scoped estate is directly threatened by large-scale quantum
    computers. Priority is given to asymmetry-based primitives and unrecoverable-data
    (HNDL) exposure; symmetric and hash primitives require upgrade to remain within
    Grover / collision headroom.
  </div>
</div>
"""


def _sec_discovery(scans, kpis, family_rows) -> str:
    if scans:
        rows = "\n".join(
            f"<tr><td class='mono'>{s['id']}</td><td>{_esc(s['target'])}</td>"
            f"<td>{_esc(s['source_type'])}</td><td>{_esc(s['status'])}</td>"
            f"<td class='num'>{_esc(_fmt_dt(s['created']))}</td></tr>"
            for s in scans
        )
        scan_table = f"""
<table>
<thead><tr><th>ID</th><th>Target</th><th>Source</th><th>Status</th><th>Created</th></tr></thead>
<tbody>{rows}</tbody>
</table>"""
    else:
        scan_table = '<p class="note">No scans found within scope.</p>'

    fam_rows = "\n".join(
        f"<tr><td>{_esc(fr['label'])}</td><td class='num'>{fr['count']}</td></tr>"
        for fr in family_rows
    ) or '<tr><td colspan="2" class="note">None</td></tr>'

    return f"""
<div class="section page-break">
  <h2 class="sec"><span class="no">2</span>Discovery Pipeline</h2>
  <p>
    The discovery pipeline runs borderless scans against a target, persists raw findings,
    normalizes and deduplicates them into canonical records, and consolidates them into a
    crypto asset inventory. <b>{kpis['scans']}</b> scan(s) produced <b>{kpis['raw_findings']}</b>
    raw finding(s) and <b>{kpis['normalized_findings']}</b> normalized record(s).
  </p>
  {scan_table}
  <h3>Findings by algorithm family</h3>
  <table>
  <thead><tr><th>Family</th><th class="num">Normalized findings</th></tr></thead>
  <tbody>{fam_rows}</tbody>
  </table>
</div>
"""


def _sec_inventory(kpis, assets, asset_count) -> str:
    if assets:
        truncated = f'<p class="note">Showing the {len(assets)} highest-priority assets (of {asset_count} in scope).</p>' if asset_count > len(assets) else ""
        rows = "\n".join(
            f"<tr><td class='mono'>{_esc(a['name'])}</td>"
            f"<td>{_esc(a['family'])}</td>"
            f"<td class='mono'>{_esc(a['algorithm'] or '—')}</td>"
            f"<td class='num'>{_esc(a['key_size'] or '—')}</td>"
            f"<td class='mono'>{_esc(a['curve'] or '—')}</td>"
            f"<td>{_risk_badge(a['risk_key'], a['risk_label'])}</td>"
            f"<td class='mono small'>{_esc(a['replacement'] or '—')}</td></tr>"
            for a in assets
        )
        table = f"""
<table>
<thead><tr><th>Asset</th><th>Family</th><th>Algorithm</th><th class="num">Key size</th><th>Curve</th>
<th>Quantum risk</th><th>Recommended replacement</th></tr></thead>
<tbody>{rows}</tbody>
</table>{truncated}"""
    else:
        table = '<p class="note">No crypto assets found within scope.</p>'

    rc = kpis["risk_counts"]
    return f"""
<div class="section page-break">
  <h2 class="sec"><span class="no">3</span>Inventory &amp; Quantum Risk</h2>
  <p>
    <b>{asset_count}</b> canonical asset(s) were consolidated from normalized findings and
    classified for quantum exposure. Exposure split:
    <b>{rc['vulnerable']} vulnerable</b> (asymmetric, Shor), <b>{rc['weak']} weak</b> (MD5/SHA-1),
    <b>{rc['moderate']} moderate</b> (symmetric/organic hashes, Grover headroom),
    <b>{rc['pqc']} PQC-ready</b>, <b>{rc['unknown']} unknown</b>.
    Multiple related artefacts citing the same algorithm are consolidated into one canonical asset
    so the inventory counts unique attack surfaces, not findings.
  </p>
  {table}
  <div class="callout danger">
    <b>Mitigation guidance:</b> migrate asymmetric primitives to NIST-approved PQC —
    ML-KEM for key establishment, ML-DSA for signatures, with hybrid X25519 transitions where
    interop dictates; retain AES-256-GCM with AEAD; retire MD5/SHA-1 in favor of SHA-256/SHA-3.
  </div>
</div>
"""


def _sec_analysis(runs) -> str:
    if not runs:
        return """
<div class="section">
  <h2 class="sec"><span class="no">4</span>Analysis &amp; Assessment</h2>
  <p class="note">No analysis runs found within scope.</p>
</div>
"""

    blocks = []
    for run in runs:
        stats = run["stats"]
        blocks.append(
            f"""
<h3>Run #{run['id']} · {_esc(run['target'])}</h3>
<div class="meta" style="margin-top:2pt">
  <div><b>Status</b>{_esc(run['status'])}</div>
  <div><b>Assets</b>{stats.get('assets', 0)} assessed</div>
  <div><b>URGENT</b>{stats.get('urgent', 0)}</div>
  <div><b>CRITICAL</b>{stats.get('critical', 0)}</div>
  <div><b>HNDL-applicable</b>{stats.get('hndl_applicable', 0)}</div>
  <div><b>Created</b>{_esc(_fmt_dt(run['created']))}</div>
</div>
"""
        )
        if run["rows"]:
            rows = "\n".join(
                f"<tr><td class='mono'>{_esc(r.get('asset_id') or '—')}</td>"
                f"<td class='mono'>{_esc(r.get('algorithm') or '—')}</td>"
                f"<td>{_esc(r.get('algorithm_category') or '—')}</td>"
                f"<td>{_esc(r.get('classical_security') or '—')}</td>"
                f"<td>{_esc(r.get('hndl_risk') or '—')}</td>"
                f"<td>{_esc(r.get('overall_risk') or '—')}</td>"
                f"<td>{_severity_badge(r.get('migration_priority'))}</td>"
                f"<td>{'Yes' if r.get('quantum_vulnerable') else 'No'}</td></tr>"
                for r in run["rows"]
            )
            blocks.append(
                f"""
<table>
<thead><tr><th>Asset</th><th>Algorithm</th><th>Category</th><th>Classical</th>
<th>HNDL risk</th><th>Overall</th><th>Priority</th><th>PQ-vulnerable</th></tr></thead>
<tbody>{rows}</tbody>
</table>"""
            )
        else:
            blocks.append('<p class="note">Assessment rows will be populated once the run completes.</p>')

    return f"""
<div class="section page-break">
  <h2 class="sec"><span class="no">4</span>Analysis &amp; Assessment</h2>
  <p>
    Each completed run executes a five-stage pipeline — CBOM, risk classification, HNDL
    (harvest-now-decrypt-later), MOSCA (Migration of Post-Quantum Cryptography) scoring —
    and writes per-asset assessments into an executive summary.
  </p>
  {''.join(blocks)}
</div>
"""


def _sec_mitigation(m) -> str:
    if not m:
        return """
<div class="section page-break">
  <h2 class="sec"><span class="no">5</span>Mitigation Plan</h2>
  <p class="note">No completed mitigation plan yet. Run mitigation over a completed analysis to sequence
  the estate into migration waves with blast radius and per-asset remediation.</p>
</div>
"""

    s = m["summary"]
    blast = m["blast"] or {}
    twin = m["twin"] or {}
    key = f"{m['generated_at'] and _fmt_dt(m['generated_at'])}"

    # KPI mini-strip
    kpis = [
        ("neutral", s.get("assets", 0), f"assets · w1 {s.get('wave1', 0)} w2 {s.get('wave2', 0)} w3 {s.get('wave3', 0)}"),
        ("danger", f"{s.get('urgent', 0)} / {s.get('high_risk', 0)}", "urgent / high-risk"),
        ("warn", f"{s.get('quantum_vulnerable', 0)} / {s.get('hndl_exposed', 0)}", "PQ-vulnerable / HNDL"),
        ("warn", s.get("effort_estimate_quarters", 0), "engineering quarter(s)"),
    ]
    strip = '<div class="kpi-row">' + "".join(
        f'<div class="kpi {cls}"><div class="n">{_esc(n)}</div><div class="l">{_esc(label)}</div></div>'
        for cls, n, label in kpis
    ) + "</div>"

    exec_block = f'<h3>Executive summary</h3><p>{_esc(m["executive_summary"])}</p>' if m["executive_summary"] else ""
    quantum_block = ""
    if m["quantum_risk_narrative"] or m["qv_assets"]:
        badges = " ".join(
            f"<span class='badge b-red mono'>{_esc(q['algorithm'])} · {_esc(q['asset_id'])} · {_esc(q['service'])}</span>"
            for q in m["qv_assets"]
        )
        ca = '<div class="callout danger"><b>Quantum risk:</b> HNDL + Shor exposure. ' + (
            m["quantum_risk_narrative"] if m["quantum_risk_narrative"] else ""
        ) + f"<br><b>Post-quantum vulnerable assets:</b> {badges}</div>" if badges else ""
        quantum_block = ca if ca else (
            '<div class="callout warn"><b>Quantum risk:</b> ' + (m["quantum_risk_narrative"] or "") + "</div>"
            if m["quantum_risk_narrative"] else ""
        )

    # Digital twin
    ctx = twin.get("contexts") or {}
    abstractions = "".join(
        f"<tr><td class='mono'>{_esc(a['label'])}</td><td>{_esc(', '.join(a.get('roles') or []))}</td>"
        f"<td class='num'>{a.get('count', 0)}</td><td>{_esc(', '.join(a.get('contexts') or []))}</td></tr>"
        for a in (twin.get("abstractions") or [])
    ) or '<tr><td colspan="4" class="note">No abstractions derived.</td></tr>'
    hv = "".join(f"<li><b>{_esc(h['label'])}</b> — {_esc(h['reason'])}</li>" for h in (twin.get("high_value_points") or []))
    twin_block = f"""
<h3>Digital twin</h3>
<div class="callout">
  <b>Context:</b> app <span class="mono">{_esc(m.get('app') or '—')}</span> · exposure
  <span class="mono">{_esc(ctx.get('exposure') or '—')}</span>{' · <b style="color:var(--red)">PUBLIC</b>' if ctx.get('publicly_accessible') else ''}<br>
  <b>Data types:</b> <span class="mono">{_esc(', '.join(ctx.get('data_types') or []) or 'none labelled')}</span> ·
  <b>Services:</b> {len(ctx.get('services') or [])}
</div>
<table>
<thead><tr><th>Abstraction</th><th>Roles</th><th class="num">Assets</th><th>Contexts</th></tr></thead>
<tbody>{abstractions}</tbody>
</table>
{f'<h4 style="font-size:8.5pt">High-value points</h4><ul class="tight">{hv}</ul>' if hv else ''}
"""

    # Blast radius
    per_algo = "".join(
        f"<tr><td class='mono'>{_esc(a['algorithm'])}</td><td class='num'>{a.get('count', 0)}</td>"
        f"<td>{_severity_badge(a.get('severity'))}</td></tr>"
        for a in (m["blast"].get("per_algorithm") or [])
    ) or '<tr><td colspan="3" class="note">No algorithms derived.</td></tr>'
    blast_block = f"""
<h3>Blast radius</h3>
<p>
  Worst exposure across <b>{blast.get('affected_services', 0)}</b> service(s) and
  <b>{blast.get('affected_findings', 0)}</b> finding(s) —{' publicly reachable' if blast.get('public_surface') else ' internal-only'}.
  Severity: {_severity_badge(blast.get('severity'))}
</p>
<table>
<thead><tr><th>Algorithm</th><th class="num">Assets</th><th>Severity</th></tr></thead>
<tbody>{per_algo}</tbody>
</table>
<div class="callout warn"><b>Poorest link:</b> {_esc(blast.get('poorest_link') or '—')} — the weakest primitive bounds the whole estate's PQC readiness.</div>
"""

    # Waves
    wave_cards = []
    for i, w in enumerate(m["waves"], start=1):
        cls = ("red", "amber", "green")[min(i - 1, 2)]
        assets = " ".join(f"<span class='badge b-{cls}'>{_esc(x)}</span>" for x in (w.get("assets") or []))
        wave_cards.append(
            f"<div class='kpi {cls}' style='border-top:2pt solid transparent'><div class='l'>Wave {i} · {_esc(w.get('timeline') or '')}</div>"
            f"<div style='font-weight:700'>{_esc(w.get('name') or '')}</div><div class='small'>{_esc(w.get('focus') or '')}</div>"
            f"{('<div style=\'margin-top:3pt\'>' + assets + '</div>') if assets else ''}</div>"
        )
    waves_block = f"""<h3>AI-optimized migration waves</h3><div class="kpi-row">{"".join(wave_cards)}</div>""" if m["waves"] else ""

    # Strategic recommendations
    strategic = "".join(
        f"<div class='kpi'><div class='l'>recommendation</div><div style='font-weight:700'>{_esc(x.get('title') or '')}</div>"
        f"<div class='small'>{_esc(x.get('description') or '')}</div>"
        f"{('<div class=\'small\'>Timeline: ' + _esc(x.get('timeline') or '') + '</div>') if x.get('timeline') else ''}</div>"
        for x in m["strategic"]
    )
    strategic_block = f"""<h3>Strategic recommendations</h3><div class="kpi-row">{strategic}</div>""" if m["strategic"] else ""

    # Prioritized remediation table
    rows_html = "".join(
        f"<tr><td class='mono'>{_esc(r['asset_id'] or '—')}</td>"
        f"<td class='mono'>{_esc(r['algorithm'] or '—')}{' '+('<span class=\'badge b-red\'>PQ</span>' if r.get('quantum_vulnerable') else '')}</td>"
        f"<td>{_severity_badge(r.get('migration_priority'))}</td>"
        f"<td>{_severity_badge((r.get('blast_radius') or {}).get('severity'))}<br><span class='small'>{_esc((r.get('blast_radius') or {}).get('shared_assets', 0))} shared · {_esc(r.get('service') or '')}</span></td>"
        f"<td class='mono'>{_esc((r.get('migration_impact') or {}).get('replacement') or '—')}</td>"
        f"<td>{_esc((r.get('migration_impact') or {}).get('effort') or '—')}</td>"
        f"<td class='num'>{_esc(r.get('migration_wave') or '—')}</td>"
        f"<td class='small'>{'<br>'.join('• '+_esc(x) for x in (r.get('suggestions') or []))}</td></tr>"
        for r in m["rows"]
    ) or '<tr><td colspan="8" class="note">Rows appear once the plan is generated.</td></tr>'

    return f"""
<div class="section page-break">
  <h2 class="sec"><span class="no">5</span>Mitigation Plan</h2>
  <div class="meta" style="margin-top:2pt">
    <div><b>Plan</b>#{m['plan_id']}</div><div><b>Analysis run</b>#{m['run_id']}</div>
    <div><b>Generated</b>{_esc(key)}</div>
    <div><b>Narration</b>{'AI-enhanced · ' + _esc(m['model_used']) if m['enhanced'] else 'deterministic baseline'}</div>
  </div>
  {strip}
  {exec_block}
  {quantum_block}
  <div class="grid2">
    <div>{twin_block}</div>
    <div>{blast_block}</div>
  </div>
  {waves_block}
  {strategic_block}
  <h3>Prioritized remediation</h3>
  <table>
  <thead><tr><th>Asset</th><th>Algorithm</th><th>Priority</th><th>Blast</th><th>Replacement</th>
  <th>Effort</th><th class="num">Wave</th><th>Actions / suggestions</th></tr></thead>
  <tbody>{rows_html}</tbody>
  </table>
</div>
"""


def _sec_appendix(meta, full_data) -> str:
    run_ids = ", ".join(str(r["id"]) for r in full_data["runs"][:8]) or "—"
    out = f"""
<div class="section page-break">
  <h2 class="sec"><span class="no">6</span>Appendix</h2>
  <h3>Method notes</h3>
  <ul class="tight">
    <li><b>CBOM</b> — Cryptographic Bill of Materials: every crypto artefact (algorithms, keys, certificates, protocols, libraries, HSMs, cloud services) discovered across the estate.</li>
    <li><b>HNDL</b> — harvest-now-decrypt-later: data currently transmitted with classical crypto is at risk the moment a CRQC (cryptographically relevant quantum computer) arrives.</li>
    <li><b>MOSCA</b> — migration-of-post-quantum-cryptography scoring: x + y &lt; z, scheduler horizon vs. data confidentiality horizon vs. migration time.</li>
    <li>Included workspaces: {_esc(meta['scope_label'])}. Rows are consolidated by canonical asset identity; findings are counted at raw and normalized layers for lineage auditability.</li>
  </ul>
  <h3>Run ledger</h3>
  <p class="small">Analysis run IDs in scope, newest first: {_esc(run_ids)}. Graph correlation produces asset-to-asset relations within the estate ({full_data['relation_count']} edge(s)).</p>
</div>
"""

    return out


# ---------------------------------------------------------------------------
# Assembler
# ---------------------------------------------------------------------------

def render(full: dict) -> str:
    meta = full["meta"]
    kpis = full["kpis"]
    body = "\n".join(
        [
            _sec_cover(meta, kpis),
            _sec_exec(kpis, full["mitigation"]),
            _sec_discovery(full["scans"], kpis, full["family_rows"]),
            _sec_inventory(kpis, full["assets"], full["asset_count"]),
            _sec_analysis(full["runs"]),
            _sec_mitigation(full["mitigation"]),
            _sec_appendix(meta, full),
        ]
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(meta['app'])} · {_esc(meta['subtitle'])}</title>
<style>{_PAGE_CSS}</style>
</head>
<body>
{body}
</body>
</html>
"""


def build_report(sid=None, db=None) -> dict:
    """Collect the full scope and render the enterprise HTML document."""
    sid, db = _scoped(db)
    data = collect(sid=sid, db=db)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    html = render(data)
    return {
        "html": html,
        "filename": f"ECDAT_FullPipeline_{stamp}.pdf",
        "data": data,
    }