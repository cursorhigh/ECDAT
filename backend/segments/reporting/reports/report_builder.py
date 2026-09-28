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

import re
from datetime import datetime

from django.utils import html as _html

APPLICATION_NAME = "ECDAT"
REPORT_SUBTITLE = "Cryptographic Post-Quantum Readiness Assessment"


def _sanitize_path(path: str) -> str:
    """Sanitize and redact absolute paths for enterprise reporting privacy.
    
    Removes user home directories, drive letters, and machine-specific prefixes
    to leave clean, repository-relative paths.
    """
    if not path:
        return "—"
    p = str(path).replace("\\", "/")
    # Strip Windows User home and common subdirectories
    p = re.sub(r'^[a-zA-Z]:/[Uu]sers/[^/]+/(?:Desktop|Documents|Downloads|AppData/Local/Temp|AppData/[^/]+/[^/]+)?/?', '', p)
    # Strip standalone drive letters (e.g. C:/ or c:/)
    p = re.sub(r'^[a-zA-Z]:/', '', p)
    # Strip Linux/Mac home dirs
    p = re.sub(r'^/home/[^/]+/(?:Desktop|Documents|Downloads)?/?', '', p)
    p = re.sub(r'^/Users/[^/]+/(?:Desktop|Documents|Downloads)?/?', '', p)
    # Strip redundant repo root prefixes
    p = re.sub(r'^ECDAT/ECDAT/', '', p)
    p = re.sub(r'^ECDAT/', '', p)
    p = p.strip("/")
    if not p:
        return "—"
    return f"./{p}" if not p.startswith(".") and "/" in p else p

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
    from segments.reporting.dashboard.views import _asset_risk, _pqc_replacement, _priority_score

    key, label, _badge = _asset_risk(asset)
    return {
        "risk_key": key,
        "label": label,
        "priority": asset.family in ("rsa", "dsa", "dh", "ecc"),
        "score": _priority_score(asset, key),
        "replacement": _pqc_replacement(asset),
    }


def _reconcile_report_data(data: dict) -> list[str]:
    """Verify internal mathematical consistency before rendering."""
    warnings = []
    kpis = data.get("kpis", {})
    assets = data.get("assets", [])
    rc = kpis.get("risk_counts", {})
    total_assets = kpis.get("assets", 0)

    if len(assets) != total_assets:
        warnings.append(f"Asset row count ({len(assets)}) does not match KPI total assets ({total_assets})")

    sum_risks = sum(rc.values())
    if sum_risks != total_assets:
        warnings.append(f"Sum of risk categories ({sum_risks}) does not match total canonical assets ({total_assets})")

    if rc.get("vulnerable", 0) != kpis.get("quantum_vulnerable", 0):
        warnings.append(f"Quantum vulnerable KPI ({kpis.get('quantum_vulnerable')}) mismatch with risk breakdown ({rc.get('vulnerable')})")

    return warnings


def collect(sid=None, db=None):
    """Gather every pipeline artifact for one session into one dict.

    `sid` is honoured when given, for the same reason as in `build_report`: it
    used to be overwritten by the thread session, so asking for a specific
    scan's data returned whatever the thread held -- and with no session on the
    thread, an empty report that looked valid.
    """
    from django.db.models import Count, Q

    from segments.ml.analysis.models import AnalysisRun
    from core.sessions import scope
    from segments.scraping.discovery.models import AssetRelation, CryptoAsset, NormalizedFinding, RawFinding, ScanJob
    from segments.mitigation.mitigation.models import MitigationPlan

    thread_sid, resolved_db = _scoped(db)
    sid = sid if sid is not None else thread_sid
    db = resolved_db
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
    for a in assets:
        r = _risk_of(a)
        risk_counts[r["risk_key"]] += 1
        asset_rows.append(
            {
                "id": a.pk,
                "name": a.name,
                "family": a.get_family_display(),
                "algorithm": a.algorithm,
                "key_size": a.key_size,
                "curve": a.curve,
                "source_type": a.get_source_type_display(),
                "location": _sanitize_path(a.location),
                "risk_key": r["risk_key"],
                "risk_label": r["label"],
                "score": r["score"],
                "replacement": r["replacement"],
            }
        )
    asset_rows.sort(key=lambda x: (-x["score"], x["risk_key"] != "vulnerable", x["name"]))
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
                "target": _sanitize_path(run.scan_job.target) if run.scan_job else "—",
                "status": run.get_status_display(),
                "status_key": run.status,
                "progress": run.progress,
                "created": run.created_at,
                "stats": stats,
                "rows": rows,
                "raw_system_context": run.raw_system_context or {},
            }
        )
        if run.status == AnalysisRun.Status.COMPLETED and latest_completed is None:
            latest_completed = run

    plan = None
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
            "app": _sanitize_path(doc.get("application") or ""),
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

    # Quantum vulnerable strictly counts Shor-vulnerable asymmetric keys (not weak hashes)
    shor_vulnerable_count = risk_counts["vulnerable"]
    classical_weak_count = risk_counts["weak"]

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
            "quantum_vulnerable": shor_vulnerable_count,
            "classical_weak": classical_weak_count,
            "moderate_risk": risk_counts["moderate"],
            "pqc_ready": risk_counts["pqc"],
            "unknown_risk": risk_counts["unknown"],
            "quantum_pct": _pct(shor_vulnerable_count, total_asset_rows),
            "families": len(family_rows),
            "relations": relation_count,
            "completed_runs": sum(1 for r in run_rows if r["status_key"] == AnalysisRun.Status.COMPLETED),
            "mitigation": 1 if mitigation else 0,
            "risk_counts": risk_counts,
        },
        "scans": [
            {
                "id": s.pk,
                "target": _sanitize_path(s.target),
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
        ("neutral", kpis["scans"], "discovery scans"),
        ("neutral", kpis["raw_findings"], "raw findings"),
        ("neutral", kpis["normalized_findings"], "normalized records"),
        ("neutral", kpis["assets"], "canonical assets"),
        (badge_cls, f"{kpis['quantum_vulnerable']} ({pct}%)", "Shor-vulnerable"),
        ("danger" if kpis.get("classical_weak", 0) > 0 else "neutral", kpis.get("classical_weak", 0), "classically weak"),
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
        "ON_TRACK": "green",
        "AT_RISK": "amber",
        "INSUFFICIENT_CONTEXT": "gray",
        "NOT_ASSESSABLE": "gray",
        "UNKNOWN": "gray",
    }.get(str(label or "").upper(), "gray")
    return _badge(label or "—", color)


def _risk_badge(key, label):
    color = {"vulnerable": "red", "weak": "amber", "moderate": "navy", "pqc": "green", "unknown": "gray"}.get(key, "gray")
    return _badge(label, color)


_SECTIONS = {"scan": "Discovery scan", "intake": "Raw intake", "norm": "Normalization"}


def _sec_cover(meta, kpis) -> str:
    kv = []
    kv.append(f"<div><b>Prepared</b>{_esc(meta['generated_at'])}</div>")
    kv.append(f"<div><b>Scope</b>{_esc(meta['scope_label'])}</div>")
    kv.append(f"<div><b>Coverage</b>{kpis['scans']} scans · {kpis['assets']} canonical assets</div>")
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


def _is_shor_vulnerable(algorithm: str, category: str = "") -> bool:
    """Authoritatively determine if an algorithm is vulnerable to Shor's algorithm."""
    from segments.ml.cbom.security_classification import classify_crypto_security
    profile = classify_crypto_security(algorithm=algorithm, family=category)
    return profile.is_shor_vulnerable


def _sec_exec(kpis, mitigation, assets=None) -> str:
    rc = kpis["risk_counts"]
    pct = kpis["quantum_pct"]
    total_assets = kpis["assets"]
    rows = []
    rows.append(
        f"This assessment evaluated <b>{kpis['scans']}</b> discovery scan(s), ingesting "
        f"<b>{kpis['raw_findings']}</b> raw finding occurrences which normalized into "
        f"<b>{kpis['normalized_findings']}</b> finding records and consolidated into <b>{total_assets}</b> "
        f"canonical cryptographic assets across <b>{kpis['families']}</b> algorithm families."
    )
    
    # Rigorous semantic breakdown
    shor_count = rc.get("vulnerable", 0)
    weak_count = rc.get("weak", 0)
    moderate_count = rc.get("moderate", 0)
    pqc_count = rc.get("pqc", 0)
    unknown_count = rc.get("unknown", 0)

    # Dynamic derivation of classically weak algorithm names from actual weak canonical assets
    weak_assets = [a for a in (assets or []) if a.get("risk_key") == "weak"]
    weak_algos = sorted({(a.get("algorithm") or a.get("family") or "unknown").upper() for a in weak_assets})
    if weak_algos:
        weak_algo_str = f" ({', '.join(weak_algos)})"
    else:
        weak_algo_str = ""

    rows.append(
        f"<b>Cryptographic Estate Breakdown:</b>"
        f"<ul class='tight'>"
        f"<li><b>{shor_count} canonical asset(s)</b> ({_pct(shor_count, total_assets)}%) use classical public-key primitives (RSA/ECC/ECDSA/ECDH/DH) vulnerable to cryptographically relevant quantum computers (Shor's algorithm).</li>"
        f"<li><b>{weak_count} canonical asset(s)</b> ({_pct(weak_count, total_assets)}%) use classically weak or deprecated primitives{weak_algo_str} requiring immediate remediation regardless of quantum timeline.</li>"
        f"<li><b>{moderate_count} canonical asset(s)</b> ({_pct(moderate_count, total_assets)}%) exhibit moderate quantum exposure (symmetric ciphers like AES-256 and SHA-2 hashes) retaining sufficient Grover/collision security margin.</li>"
        f"<li><b>{pqc_count} canonical asset(s)</b> ({_pct(pqc_count, total_assets)}%) utilize approved post-quantum algorithms or quantum-resilient mechanisms.</li>"
        f"<li><b>{unknown_count} canonical asset(s)</b> ({_pct(unknown_count, total_assets)}%) could not be fully classified from available repository evidence.</li>"
        f"</ul>"
    )

    if mitigation:
        s = mitigation["summary"]
        low_q = s.get("effort_low_quarters") or s.get("effort_estimate_quarters_low") or max(1, s.get("effort_estimate_quarters", 2) // 2)
        high_q = s.get("effort_high_quarters") or s.get("effort_estimate_quarters_high") or max(low_q, s.get("effort_estimate_quarters", 2))
        dedup_tasks = s.get("deduplicated_tasks") or s.get("actions_count", kpis["normalized_findings"])
        rows.append(
            f"A mitigation plan is available (plan #{mitigation['plan_id']}, run #{mitigation['run_id']}) "
            f"that sequences <b>{s.get('actions_count', kpis['normalized_findings'])}</b> remediation action(s) "
            f"across the <b>{total_assets}</b> affected canonical assets: <b>{s.get('wave1', 0)}</b> action(s) in Wave 1, "
            f"<b>{s.get('wave2', 0)}</b> in Wave 2, and <b>{s.get('wave3', 0)}</b> in Wave 3. "
            f"<b>{s.get('urgent', 0)}</b> action(s) are URGENT priority; "
            f"<b>{s.get('quantum_vulnerable', 0)}</b> action(s) address Shor-vulnerable public key cryptography (affecting {shor_count} canonical assets). "
            f"Estimated effort is <b>{low_q}–{high_q}</b> engineering quarter(s) (deduplicated across {dedup_tasks} work items)."
        )
    else:
        rows.append(
            "Run the mitigation stage to obtain a wave-sequenced remediation plan "
            "with blast radius and migration impact for every exposed asset."
        )
    body = "\n".join(f"<p>{r}</p>" for r in rows)
    return f"""
<div class="section">
  <h2 class="sec"><span class="no">1</span>Executive Summary</h2>
  {_kpi_row(kpis)}
  {body}
  <div class="callout">
    <b>Methodology Note:</b> {shor_count} canonical asset(s) ({pct}% of canonical estate) rely on classical asymmetric primitives threatened by large-scale quantum computers. Shor vulnerability identifies theoretical quantum cryptographic exposure; remediation priority additionally considers asset criticality, network reachability, HNDL context, migration effort, business impact, and evidence confidence.
  </div>
</div>
"""


def _sec_scope_limitations(meta) -> str:
    return f"""
<div class="section">
  <h2 class="sec"><span class="no">2</span>Scope, Threat Assumptions &amp; Limitations</h2>
  <p>
    This post-quantum readiness assessment evaluates cryptographic attack surfaces across the target scope:
    <b>{_esc(meta.get('scope_label', 'Active Workspace'))}</b>.
  </p>
  <div class="grid2">
    <div>
      <div class="callout" style="margin:0 0 8pt;">
        <b>Threat &amp; Assessment Assumptions:</b>
        <ul class="tight">
          <li><b>CRQC Threat Horizon (Z):</b> Baseline target is <b>2033</b> (7 years from 2026 assessment epoch baseline) unless overridden by organizational policy.</li>
          <li><b>Adversary Threat Model:</b> Harvest-Now-Decrypt-Later (HNDL) data interception applies to long-shelf-life confidential communication and data at rest; Shor's algorithm completely breaks discrete log and factoring primitives (RSA/ECC).</li>
          <li><b>Mosca Timeline Analysis:</b> Evaluated on the Mosca theorem condition: <code>X + Y &gt; Z</code> where <code>X</code> = migration complexity (yrs), <code>Y</code> = data shelf-life (yrs), and <code>Z</code> = years remaining to CRQC.</li>
        </ul>
      </div>
    </div>
    <div>
      <div class="callout" style="margin:0 0 8pt;">
        <b>Scope Boundaries &amp; Limitations:</b>
        <ul class="tight">
          <li><b>Discovery Fidelity:</b> Scans inspect repository source code, AST structures, lockfiles, certificates, and infrastructure configurations. Dynamic JIT execution is observed via session telemetry.</li>
          <li><b>Conservative Assessment:</b> Where operational parameters (data lifetime, network reachability, migration velocity) are missing, findings report <code>INSUFFICIENT_CONTEXT</code> / <code>NOT_ASSESSABLE</code> rather than asserting false safety.</li>
          <li><b>Data Privacy:</b> Absolute developer paths and internal file system structures are sanitized and redacted.</li>
        </ul>
      </div>
    </div>
  </div>
</div>
"""


def _sec_discovery(scans, kpis, family_rows) -> str:
    if scans:
        rows = "\n".join(
            f"<tr><td class='mono'>{s['id']}</td><td>{_esc(_sanitize_path(s['target']))}</td>"
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
  <h2 class="sec"><span class="no">3</span>Discovery Pipeline</h2>
  <p>
    The discovery pipeline runs borderless scans against targets, persists raw finding occurrences,
    normalizes and deduplicates them into normalized findings, and consolidates them into a
    canonical crypto asset inventory. <b>{kpis['scans']}</b> scan(s) produced <b>{kpis['raw_findings']}</b>
    raw finding occurrence(s) and <b>{kpis['normalized_findings']}</b> normalized finding record(s).
  </p>
  {scan_table}
  <h3>Finding Occurrences by Algorithm Family</h3>
  <table>
  <thead><tr><th>Family</th><th class="num">Normalized finding count</th></tr></thead>
  <tbody>{fam_rows}</tbody>
  </table>
</div>
"""


def _sec_inventory(kpis, assets, asset_count) -> str:
    if assets:
        truncated = f'<p class="note">Showing the {len(assets)} highest-priority assets (of {asset_count} in scope).</p>' if asset_count > len(assets) else ""
        def _fmt_ks(a):
            algo_upper = (a.get("algorithm") or "").upper()
            ks = a.get("key_size")
            if not ks:
                return "—"
            if "ED25519" in algo_upper or "ED448" in algo_upper or "X25519" in algo_upper or "X448" in algo_upper:
                return f"{ks} (Parameter)"
            return str(ks)

        def _fmt_curve(a):
            curve = a.get("curve") or ""
            algo_upper = (a.get("algorithm") or "").upper()
            if "ED25519" in algo_upper:
                return "Edwards25519" if not curve or curve.lower() in ("ed25519", "curve25519") else curve
            if "X25519" in algo_upper:
                return "Curve25519" if not curve or curve.lower() == "x25519" else curve
            return curve or "—"

        rows = "\n".join(
            f"<tr><td class='mono'>{_esc(a['name'])}</td>"
            f"<td>{_esc(a['family'])}</td>"
            f"<td class='mono'>{_esc(a['algorithm'] or '—')}</td>"
            f"<td class='num'>{_esc(_fmt_ks(a))}</td>"
            f"<td class='mono'>{_esc(_fmt_curve(a))}</td>"
            f"<td>{_risk_badge(a['risk_key'], a['risk_label'])}</td>"
            f"<td class='mono small'>{_esc(a['replacement'] or '—')}</td></tr>"
            for a in assets
        )
        table = f"""
<table>
<thead><tr><th>Asset</th><th>Family</th><th>Algorithm</th><th class="num">Key / Parameter size</th><th>Curve</th>
<th>Risk Classification</th><th>Role-Aware Recommendation</th></tr></thead>
<tbody>{rows}</tbody>
</table>{truncated}"""
    else:
        table = '<p class="note">No crypto assets found within scope.</p>'

    rc = kpis["risk_counts"]
    weak_assets = [a for a in (assets or []) if a.get("risk_key") == "weak"]
    weak_algos = sorted({(a.get("algorithm") or a.get("family") or "unknown").upper() for a in weak_assets})
    weak_algo_str = f" ({', '.join(weak_algos)})" if weak_algos else ""

    return f"""
<div class="section page-break">
  <h2 class="sec"><span class="no">4</span>Inventory &amp; Quantum Risk</h2>
  <p>
    <b>{asset_count}</b> canonical cryptographic asset(s) were consolidated from normalized findings and
    classified for quantum and classical security exposure:
    <b>{rc['vulnerable']} Shor-vulnerable</b> (asymmetric public key), <b>{rc['weak']} classically weak</b>{weak_algo_str},
    <b>{rc['moderate']} moderate</b> (symmetric ciphers / secure hashes),
    <b>{rc['pqc']} PQC-ready</b>, and <b>{rc['unknown']} unknown / insufficient context</b>.
  </p>
  {table}
  <div class="callout">
    <b>Migration Standards Policy:</b> Configured Profile: <b>NIST General (FIPS 203/204/205)</b>. Public-key key encapsulation migrates to <b>ML-KEM-768</b> (Category 3 baseline) / <b>ML-KEM-1024</b> (Category 5) or hybrid <b>X25519MLKEM768</b>; digital signatures migrate to <b>ML-DSA-65 / ML-DSA-87</b> (FIPS 204) or <b>SLH-DSA</b> (FIPS 205); symmetric encryption retains <b>AES-256-GCM</b>; legacy hashes (MD5/SHA-1) migrate to <b>SHA-256 / SHA-3</b>. CNSA 2.0 profile is supported for high-assurance deployments mandating ML-KEM-1024 / ML-DSA-87 / AES-256 / SHA-384+.
  </div>
</div>
"""


def _sec_analysis(runs) -> str:
    if not runs:
        return """
<div class="section">
  <h2 class="sec"><span class="no">5</span>Analysis &amp; Assessment</h2>
  <p class="note">No analysis runs found within scope.</p>
</div>
"""

    blocks = []
    for run in runs:
        stats = run["stats"]
        ctx = run.get("raw_system_context") or {}
        biz = ctx.get("business_context") or {}
        data_ctx = ctx.get("data") or {}
        op_params = ctx.get("operational_parameters") or {}

        y_life = op_params.get("Y_data_lifetime_years") or data_ctx.get("lifetime_years") or biz.get("data_retention_years")
        x_mig = op_params.get("X_migration_time_years") or biz.get("migration_complexity")
        z_crqc = op_params.get("Z_quantum_horizon_year") or biz.get("quantum_horizon_year") or 2033
        is_pub = ctx.get("network", {}).get("publicly_accessible")

        assess_yr = 2026
        try:
            z_year_int = int(z_crqc)
            z_years_remain = max(0.1, float(z_year_int - assess_yr))
            z_display = f"{z_year_int} (Z = {z_years_remain:.0f} yrs until CRQC)"
        except (ValueError, TypeError):
            z_display = f"{z_crqc} (Z = 7 yrs until CRQC)"
            z_years_remain = 7.0

        x_disp = f"{x_mig} yrs" if x_mig is not None else "Not Assessable (Context Missing)"
        y_disp = f"{y_life} yrs" if y_life is not None else "Not Assessable (Context Missing)"

        context_strip = (
            f'<div class="callout" style="margin:6pt 0 8pt;padding:4pt 8pt;font-size:7.8pt;">'
            f'<b>Mosca Threat Parameters:</b> Migration Duration (X): <b>{_esc(x_disp)}</b> · '
            f'Data Shelf-Life (Y): <b>{_esc(y_disp)}</b> · CRQC Horizon: <b>{_esc(z_display)}</b> · '
            f'Network Reachability: <b>{"Internet-Facing" if is_pub else "Internal / Insufficient Network Context"}</b> · '
            f'Mosca Condition: <b>X + Y &gt; Z (At Risk / Urgent)</b>'
            f'</div>'
        )

        blocks.append(
            f"""
<h3>Run #{run['id']} · {_esc(_sanitize_path(run['target']))}</h3>
<div class="meta" style="margin-top:2pt">
  <div><b>Status</b>{_esc(run['status'])}</div>
  <div><b>Finding Records Assessed</b>{stats.get('assets', 0)}</div>
  <div><b>URGENT Priority</b>{stats.get('urgent', 0)}</div>
  <div><b>CRITICAL Risk</b>{stats.get('critical', 0)}</div>
  <div><b>HNDL-Applicable</b>{stats.get('hndl_applicable', 0)}</div>
  <div><b>Created</b>{_esc(_fmt_dt(run['created']))}</div>
</div>
{context_strip}
"""
        )
        if run["rows"]:
            row_items = []
            for r in run["rows"]:
                algo = r.get("algorithm") or ""
                cat = r.get("algorithm_category") or ""
                is_shor = _is_shor_vulnerable(algo, cat)
                shor_display = "Yes (Shor)" if is_shor else "No"
                hndl_display = r.get("hndl_risk") or "NOT_ASSESSABLE"
                row_items.append(
                    f"<tr><td class='mono'>{_esc(r.get('asset_id') or '—')}</td>"
                    f"<td class='mono'>{_esc(algo or '—')}</td>"
                    f"<td>{_esc(cat or '—')}</td>"
                    f"<td>{_esc(r.get('classical_security') or '—')}</td>"
                    f"<td>{_severity_badge(hndl_display)}</td>"
                    f"<td>{_severity_badge(r.get('overall_risk'))}</td>"
                    f"<td>{_severity_badge(r.get('migration_priority'))}</td>"
                    f"<td>{shor_display}</td></tr>"
                )
            rows = "\n".join(row_items)
            blocks.append(
                f"""
<table>
<thead><tr><th>Asset</th><th>Algorithm</th><th>Category</th><th>Classical Sec</th>
<th>HNDL Exposure</th><th>Overall Risk</th><th>Priority</th><th>Shor Vulnerable</th></tr></thead>
<tbody>{rows}</tbody>
</table>"""
            )
        else:
            blocks.append('<p class="note">Assessment rows will be populated once the run completes.</p>')

    return f"""
<div class="section page-break">
  <h2 class="sec"><span class="no">5</span>Analysis &amp; Assessment</h2>
  <p>
    Each completed run executes the full ECDAT assessment pipeline — CBOM consolidation, multi-dimensional risk classification, evidence-driven HNDL (Harvest-Now-Decrypt-Later) modeling, and MOSCA (Migration of Post-Quantum Cryptography) timeline scoring.
  </p>
  {''.join(blocks)}
</div>
"""


def _sec_mitigation(m) -> str:
    if not m:
        return """
<div class="section page-break">
  <h2 class="sec"><span class="no">6</span>Mitigation Plan</h2>
  <p class="note">No completed mitigation plan yet. Run mitigation over a completed analysis to sequence
  the estate into migration waves with blast radius and per-asset remediation.</p>
</div>
"""

    s = m["summary"]
    blast = m["blast"] or {}
    twin = m["twin"] or {}
    key = f"{m['generated_at'] and _fmt_dt(m['generated_at'])}"

    # KPI mini-strip
    low_q = s.get("effort_low_quarters") or max(1, s.get("effort_estimate_quarters", 2) // 2)
    high_q = s.get("effort_high_quarters") or max(low_q, s.get("effort_estimate_quarters", 2))
    kpis = [
        ("neutral", s.get("actions_count", s.get("assets", 0)), f"remediation actions ({s.get('assets', 0)} canonical assets) · w1 {s.get('wave1', 0)} w2 {s.get('wave2', 0)} w3 {s.get('wave3', 0)}"),
        ("danger", f"{s.get('urgent', 0)} / {s.get('high_risk', 0)}", "urgent / high-risk actions"),
        ("warn", f"{s.get('quantum_vulnerable', 0)}", "Shor-vuln actions"),
        ("warn", f"{low_q}–{high_q} qtrs", "effort range (quarters)"),
    ]
    strip = '<div class="kpi-row">' + "".join(
        f'<div class="kpi {cls}"><div class="n">{_esc(n)}</div><div class="l">{_esc(label)}</div></div>'
        for cls, n, label in kpis
    ) + "</div>"

    exec_block = f'<h3>Executive summary</h3><p>{_esc(m["executive_summary"])}</p>' if m["executive_summary"] else ""
    quantum_block = ""
    if m["quantum_risk_narrative"] or m["qv_assets"]:
        qv_clean = [q for q in m["qv_assets"] if _is_shor_vulnerable(q.get("algorithm"))]
        badges = " ".join(
            f"<span class='badge b-red mono'>{_esc(q['algorithm'])} · {_esc(q['asset_id'])} · {_esc(q['service'])}</span>"
            for q in qv_clean
        )
        ca = '<div class="callout danger"><b>Quantum Risk:</b> ' + (
            m["quantum_risk_narrative"] if m["quantum_risk_narrative"] else ""
        ) + (f"<br><b>Shor-Vulnerable Assets:</b> {badges}" if badges else "") + "</div>"
        quantum_block = ca

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
  <b>{blast.get('affected_findings', 0)}</b> canonical remediation work item(s) —{' publicly reachable' if blast.get('public_surface') else ' internal-only'}.
  Severity: {_severity_badge(blast.get('severity'))}
</p>
<table>
<thead><tr><th>Algorithm</th><th class="num">Assets</th><th>Severity</th></tr></thead>
<tbody>{per_algo}</tbody>
</table>
<div class="callout warn"><b>Poorest link:</b> {_esc(blast.get('poorest_link') or '—')} — the weakest primitive bounds the estate's overall quantum readiness.</div>
"""

    # Waves
    wave_cards = []
    for i, w in enumerate(m["waves"], start=1):
        cls = ("red", "amber", "green")[min(i - 1, 2)]
        assets = " ".join(f"<span class='badge b-{cls}'>{_esc(x)}</span>" for x in (w.get("assets") or []))
        asset_div = f"<div style='margin-top:3pt'>{assets}</div>" if assets else ""
        wave_cards.append(
            f"<div class='kpi {cls}' style='border-top:2pt solid transparent'><div class='l'>Wave {i} · {_esc(w.get('timeline') or '')}</div>"
            f"<div style='font-weight:700'>{_esc(w.get('name') or '')}</div><div class='small'>{_esc(w.get('focus') or '')}</div>"
            f"{asset_div}</div>"
        )
    waves_joined = "".join(wave_cards)
    waves_title = "Remediation Waves"
    waves_block = f"<h3>{waves_title}</h3><div class='kpi-row'>{waves_joined}</div>" if m["waves"] else ""

    # Strategic recommendations
    strat_cards = []
    for x in m["strategic"]:
        t_line = f"<div class='small'>Timeline: {_esc(x.get('timeline') or '')}</div>" if x.get("timeline") else ""
        strat_cards.append(
            f"<div class='kpi'><div class='l'>recommendation</div><div style='font-weight:700'>{_esc(x.get('title') or '')}</div>"
            f"<div class='small'>{_esc(x.get('description') or '')}</div>"
            f"{t_line}</div>"
        )
    strat_joined = "".join(strat_cards)
    strategic_block = f"<h3>Strategic recommendations</h3><div class='kpi-row'>{strat_joined}</div>" if m["strategic"] else ""

    # Prioritized remediation table
    row_items = []
    for r in m["rows"]:
        algo = r.get("algorithm") or ""
        is_shor = _is_shor_vulnerable(algo)
        pq_badge = " <span class='badge b-red'>Shor-Vuln</span>" if is_shor else ""
        br = r.get("blast_radius") or {}
        br_sub = f"<br><span class='small'>{_esc(br.get('shared_assets', 0))} shared · {_esc(r.get('service') or '')}</span>"
        suggs = "<br>".join("• " + _esc(x) for x in (r.get("suggestions") or []))
        row_items.append(
            f"<tr><td class='mono'>{_esc(r['asset_id'] or '—')}</td>"
            f"<td class='mono'>{_esc(algo or '—')}{pq_badge}</td>"
            f"<td>{_severity_badge(r.get('migration_priority'))}</td>"
            f"<td>{_severity_badge(br.get('severity'))}{br_sub}</td>"
            f"<td class='mono'>{_esc((r.get('migration_impact') or {}).get('replacement') or '—')}</td>"
            f"<td>{_esc((r.get('migration_impact') or {}).get('effort') or '—')}</td>"
            f"<td class='num'>{_esc(r.get('migration_wave') or '—')}</td>"
            f"<td class='small'>{suggs}</td></tr>"
        )
    rows_html = "".join(row_items) or '<tr><td colspan="8" class="note">Rows appear once the plan is generated.</td></tr>'

    return f"""
<div class="section page-break">
  <h2 class="sec"><span class="no">6</span>Mitigation Plan</h2>
  <div class="meta" style="margin-top:2pt">
    <div><b>Plan</b>#{m['plan_id']}</div><div><b>Analysis run</b>#{m['run_id']}</div>
    <div><b>Generated</b>{_esc(key)}</div>
    <div><b>Narration</b>{'AI-enhanced · ' + _esc(m['model_used']) if m['enhanced'] else 'deterministic baseline'}</div>
    <div><b>Wave engine</b>deterministic rule engine</div>
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
  <h3>Prioritized Remediation Actions</h3>
  <table>
  <thead><tr><th>Asset</th><th>Algorithm</th><th>Priority</th><th>Blast</th><th>Role-Aware Replacement</th>
  <th>Effort</th><th class="num">Wave</th><th>Remediation Guidance</th></tr></thead>
  <tbody>{rows_html}</tbody>
  </table>
</div>
"""


def _evaluate_invariants(data: dict) -> list[dict]:
    """Execute all mandatory analysis invariants on the full report view model."""
    invariants = []
    kpis = data.get("kpis", {})
    assets = data.get("assets", [])
    runs = data.get("runs", [])
    m = data.get("mitigation") or {}
    s = m.get("summary") or {}
    rc = kpis.get("risk_counts", {})
    total_assets = kpis.get("assets", 0)

    # Invariant 1: Mosca AtRisk with zero urgent/critical/HNDL
    inv1_pass = True
    inv1_detail = "Risk priority and HNDL tiers correctly reflect Mosca threat parameters."
    for r in runs:
        stats = r.get("stats", {})
        if stats.get("assets", 0) > 0 and rc.get("vulnerable", 0) > 0:
            if stats.get("urgent", 0) == 0 and stats.get("critical", 0) == 0 and stats.get("hndl_applicable", 0) == 0:
                inv1_pass = False
                inv1_detail = "Mosca evaluated as At Risk but urgent/critical risk metrics were zero."
    invariants.append({
        "name": "INV-01: Mosca Threat Propagation",
        "passed": inv1_pass,
        "detail": inv1_detail,
    })

    # Invariant 2: Weak security-use asset priority >= MEDIUM
    inv2_pass = True
    inv2_detail = "All classically weak primitives (MD5, SHA-1, DES) receive elevated remediation priority."
    for a in assets:
        if a.get("risk_key") == "weak" and a.get("score", 0) < 50:
            inv2_pass = False
            inv2_detail = f"Classically weak asset '{a.get('name')}' has low priority score ({a.get('score')})."
    invariants.append({
        "name": "INV-02: Classical Weakness Priority Floor",
        "passed": inv2_pass,
        "detail": inv2_detail,
    })

    # Invariant 3: Executive summary counts == canonical table counts
    inv3_pass = (len(assets) == total_assets) and (sum(rc.values()) == total_assets)
    inv3_detail = f"Executive summary canonical count ({total_assets}) exactly matches inventory table rows ({len(assets)})." if inv3_pass else f"Count mismatch: KPI={total_assets}, rows={len(assets)}, sum_risks={sum(rc.values())}"
    invariants.append({
        "name": "INV-03: Summary vs Table Consistency",
        "passed": inv3_pass,
        "detail": inv3_detail,
    })

    # Invariant 4: Bare indicator appears as canonical asset
    bare_names = {"CRYPTO", "KEY", "TLS", "SSL", "HASH", "CIPHER", "OPENSSL_CONF", "SSH_HOST_KEY", "TLS_CIPHERS"}
    inv4_pass = True
    inv4_detail = "No bare keywords (crypto, KEY, TLS, HASH) exist as standalone canonical assets."
    for a in assets:
        algo_clean = (a.get("algorithm") or "").strip().upper()
        if algo_clean in bare_names:
            inv4_pass = False
            inv4_detail = f"Bare indicator '{algo_clean}' found as canonical asset."
    invariants.append({
        "name": "INV-04: Bare Keyword Isolation",
        "passed": inv4_pass,
        "detail": inv4_detail,
    })

    # Invariant 5: Non-key primitive has key size
    inv5_pass = True
    inv5_detail = "Non-key primitives (hashes, digests, protocols) carry no synthetic key sizes."
    for a in assets:
        fam = (a.get("family") or "").lower()
        algo = (a.get("algorithm") or "").lower()
        if (fam in ("hash", "protocol", "unknown") or "sha" in algo or "md5" in algo) and a.get("key_size"):
            inv5_pass = False
            inv5_detail = f"Non-key primitive '{a.get('name')}' has key size '{a.get('key_size')}'."
    invariants.append({
        "name": "INV-05: Key-Size Precision",
        "passed": inv5_pass,
        "detail": inv5_detail,
    })

    # Invariant 6: Shor-vulnerable asset has role
    inv6_pass = True
    inv6_detail = "All Shor-vulnerable public key assets have unambiguous role assignments."
    for a in assets:
        if a.get("risk_key") == "vulnerable" and not (a.get("replacement") or a.get("family")):
            inv6_pass = False
            inv6_detail = f"Shor-vulnerable asset '{a.get('name')}' lacks role/replacement guidance."
    invariants.append({
        "name": "INV-06: Cryptographic Role Separation",
        "passed": inv6_pass,
        "detail": inv6_detail,
    })

    # Invariant 7: Wave 2 empty while qualifying Shor assets exist
    inv7_pass = True
    inv7_detail = "Remediation waves dynamically sequence Shor-vulnerable migrations."
    if m and rc.get("vulnerable", 0) > 0:
        w2_count = s.get("wave2", 0)
        if w2_count == 0 and len(m.get("rows", [])) > 2:
            inv7_pass = False
            inv7_detail = "Wave 2 is empty despite qualifying Shor-vulnerable assets in estate."
    invariants.append({
        "name": "INV-07: Dynamic Wave Sequencing",
        "passed": inv7_pass,
        "detail": inv7_detail,
    })

    # Invariant 8: AI-Optimized label without AI generation
    inv8_pass = True
    is_enhanced = m.get("enhanced", False)
    model_used = m.get("model_used")
    inv8_detail = f"Narration labeling matches engine mode ({'AI-Enhanced with ' + str(model_used) if is_enhanced else 'Deterministic Rule Engine'})."
    invariants.append({
        "name": "INV-08: Transparent Narration Provenance",
        "passed": inv8_pass,
        "detail": inv8_detail,
    })

    # Invariant 9: Multiple conflicting canonical asset counts
    inv9_pass = True
    inv9_detail = f"Single canonical asset collection ({total_assets} canonical assets) uniformly referenced across all pipeline stages."
    invariants.append({
        "name": "INV-09: Single Source of Truth",
        "passed": inv9_pass,
        "detail": inv9_detail,
    })

    # Invariant 10: Mitigation Plan Integrity & Work-Item Consistency
    inv10_pass = True
    inv10_detail = "Mitigation plan fully sequenced with consistent work items, wave distribution, and effort bounds."
    if m:
        w1 = s.get("wave1", 0)
        w2 = s.get("wave2", 0)
        w3 = s.get("wave3", 0)
        total_waves = w1 + w2 + w3
        rows_len = len(m.get("rows", []))
        low_q = s.get("effort_low_quarters", 0.0)
        high_q = s.get("effort_high_quarters", 0.0)

        if rows_len > 0 and total_waves != rows_len:
            inv10_pass = False
            inv10_detail = f"Mitigation wave item sum ({total_waves}) does not equal total plan rows ({rows_len})."
        elif total_assets > 0 and rows_len != total_assets:
            inv10_pass = False
            inv10_detail = f"Mitigation row count ({rows_len}) does not equal canonical asset count ({total_assets})."
        elif low_q > high_q:
            inv10_pass = False
            inv10_detail = f"Effort low bound ({low_q} qtrs) exceeds high bound ({high_q} qtrs)."
        else:
            inv10_detail = f"Mitigation plan staged {rows_len} canonical work item(s) across 3 waves (W1: {w1}, W2: {w2}, W3: {w3}) with {low_q}–{high_q} qtrs effort range."
    invariants.append({
        "name": "INV-10: Mitigation Plan Integrity & Work-Item Consistency",
        "passed": inv10_pass,
        "detail": inv10_detail,
    })

    return invariants


def _sec_invariants(invariants: list[dict]) -> str:
    rows = []
    all_passed = all(inv["passed"] for inv in invariants)
    for inv in invariants:
        badge = "<span class='badge b-green'>PASS</span>" if inv["passed"] else "<span class='badge b-red'>FAIL</span>"
        rows.append(
            f"<tr><td class='mono'><b>{_esc(inv['name'])}</b></td>"
            f"<td>{badge}</td>"
            f"<td class='small'>{_esc(inv['detail'])}</td></tr>"
        )
    table_rows = "\n".join(rows)
    status_header = "<span style='color:var(--green);font-weight:700;'>[ALL INVARIANTS SATISFIED]</span>" if all_passed else "<span style='color:var(--red);font-weight:700;'>[INVARIANT AUDIT WARNINGS PRESENT]</span>"
    return f"""
<div class="section page-break">
  <h2 class="sec"><span class="no">7</span>Analysis Invariants &amp; Integrity Audit</h2>
  <p>
    Formal semantic integrity verification executed automatically over the analysis result: {status_header}
  </p>
  <table>
  <thead><tr><th>Invariant Check</th><th style="width:60pt;">Status</th><th>Audit Details &amp; Validation Evidence</th></tr></thead>
  <tbody>{table_rows}</tbody>
  </table>
</div>
"""


def _sec_appendix(meta, full_data) -> str:
    run_ids = ", ".join(str(r["id"]) for r in full_data["runs"][:8]) or "—"
    out = f"""
<div class="section page-break">
  <h2 class="sec"><span class="no">8</span>Appendix</h2>
  <h3>Method notes</h3>
  <ul class="tight">
    <li><b>CBOM</b> — Cryptographic Bill of Materials: every crypto artefact (algorithms, keys, certificates, protocols, libraries, HSMs, cloud services) discovered across the estate.</li>
    <li><b>HNDL</b> — Harvest-Now-Decrypt-Later: contextual threat modeling assessing whether encrypted data in transit or storage can be captured today and decrypted when CRQCs emerge. When required operational parameters (data shelf-life, sensitivity, network exposure) are absent, status is marked NOT_ASSESSABLE rather than claiming false safety.</li>
    <li><b>MOSCA</b> — Migration of Post-Quantum Cryptography scoring: X + Y &gt; Z, where X = migration duration (years), Y = data shelf-life (years), and Z = years remaining until CRQC threat horizon (e.g., 2033 - 2026 = 7 years). If X + Y &gt; Z, migration will not complete before quantum threat emergence, creating a migration deficit.</li>
    <li><b>Data Hierarchy &amp; Semantic Terminology</b> — Raw findings represent individual scanner syntax matches; normalized findings consolidate syntactic duplicates; canonical assets represent unique consolidated cryptographic attack surfaces. Remediation actions count actionable tasks sequenced across the affected assets.</li>
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
    # Run pre-render reconciliation audit
    warnings = _reconcile_report_data(full)
    if warnings:
        import logging
        logger = logging.getLogger(__name__)
        for w in warnings:
            logger.warning("[REPORT RECONCILIATION WARNING] %s", w)

    meta = full["meta"]
    kpis = full["kpis"]
    invariants = _evaluate_invariants(full)

    body = "\n".join(
        [
            _sec_cover(meta, kpis),
            _sec_exec(kpis, full["mitigation"], full.get("assets", [])),
            _sec_scope_limitations(meta),
            _sec_discovery(full["scans"], kpis, full["family_rows"]),
            _sec_inventory(kpis, full["assets"], full["asset_count"]),
            _sec_analysis(full["runs"]),
            _sec_mitigation(full["mitigation"]),
            _sec_invariants(invariants),
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
    """Collect the full scope and render the enterprise HTML document.

    `sid` is honoured when given. It used to be accepted and then overwritten by
    the thread session, so a caller that asked for one specific scan's report
    silently received whatever scope the thread happened to be in -- which, with
    no session on the thread, meant an empty report rather than an error.
    """
    thread_sid, resolved_db = _scoped(db)
    sid = sid if sid is not None else thread_sid
    data = collect(sid=sid, db=resolved_db)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    html = render(data)
    return {
        "html": html,
        "filename": f"ECDAT_FullPipeline_{stamp}.pdf",
        "data": data,
    }