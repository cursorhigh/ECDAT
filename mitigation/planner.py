"""Mitigation planning: generate prioritized remediation for a finished run.

Sits one step past ``analysis.runner`` — as soon as an AnalysisRun reaches
``completed`` the planner creates a MitigationPlan and hands it to the
mitigation agent suite (blast radius, migration impact, suggestions, optional
Gemini narrator). Follows the runner discipline: DB rows are the source of
truth, the huey task is a thin async wrapper, progress writes stay idempotent
and generation never raises — failures mark the plan failed.
"""

import logging
import os
import threading

from django.conf import settings
from django.utils import timezone
from huey.contrib.djhuey import db_task

from core.models import log_action
from core.modes import db_alias_for_mode
from mitigation_agent import MitigationAgent

from .models import MitigationPlan

logger = logging.getLogger("mitigation")


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def ensure_plan(run, db="default"):
    """Return the (existing or newly created) plan row for a run, atomically."""
    plan, _ = MitigationPlan.objects.using(db).get_or_create(
        run=run,
        defaults={
            "mode": run.mode,
            "session_id": run.session_id,
            "status": MitigationPlan.Status.PENDING,
            "progress": 0,
        },
    )
    return plan


def trigger_mitigation(run, db="default"):
    """Create a plan for a completed run and dispatch generation.

    Idempotent: a COMPLETE plan is returned untouched; a queued/generating or
    failed plan is re-dispatched so stuck rows recover. Returns the plan.
    """
    plan = ensure_plan(run, db)
    if plan.status == MitigationPlan.Status.COMPLETE:
        return plan
    log_action(
        "mitigation_queued",
        f"Queued mitigation plan for analysis run {run.pk}",
        "mitigationplan",
        plan.pk,
        mode=run.mode,
        session_id=run.session_id,
    )
    _dispatch(plan, db)
    return plan


# ---------------------------------------------------------------------------
# Dispatch (mirrors analysis.runner: thread by default, huey on demand)
# ---------------------------------------------------------------------------


def _dispatch(plan, db):
    mode = plan.mode
    if os.environ.get("ECDAT_QUEUE_ASYNC") == "1":
        generate_plan_task(plan.pk, mode)
    elif settings.HUEY.get("immediate"):
        generate_plan_task(plan.pk, mode)
    else:
        threading.Thread(
            target=_generate_safe,
            args=(plan.pk, mode),
            daemon=True,
        ).start()


def _generate_safe(plan_id, mode):
    from django.db import close_old_connections

    try:
        generate_plan(plan_id, mode)
    except Exception as exc:  # noqa: BLE001 - worker thread must survive
        logger.exception("generate_plan(%s, %s) crashed: %s", plan_id, mode, exc)
        try:
            db = db_alias_for_mode(mode)
            plan = MitigationPlan.objects.using(db).filter(pk=plan_id).first()
            if plan is not None:
                plan.status = MitigationPlan.Status.FAILED
                plan.error = str(exc)
                plan.save(using=db, update_fields=["status", "error"])
        except Exception:
            pass
    finally:
        close_old_connections()


# ---------------------------------------------------------------------------
# Generation pipeline
# ---------------------------------------------------------------------------


def generate_plan(plan_id, mode):
    """Run the mitigation agent suite for a plan and persist the document.

    Never raises: any stage failure marks the plan failed (with error text).
    Returns the plan or None when the row cannot be found.
    """
    db = db_alias_for_mode(mode)
    plan = (
        MitigationPlan.objects.using(db)
        .select_related("run__scan_job")
        .filter(pk=plan_id)
        .first()
    )
    if plan is None:
        logger.warning("generate_plan: plan %s not found in db '%s'", plan_id, db)
        return None

    run = plan.run
    try:
        plan.status = MitigationPlan.Status.GENERATING
        plan.progress = 15
        plan.error = ""
        plan.save(using=db, update_fields=["status", "progress", "error"])

        bundle = _run_bundle(run, db)
        plan.progress = 30
        plan.save(using=db, update_fields=["progress"])

        document = MitigationAgent().generate(bundle)
        plan.progress = 90
        plan.document = document
        plan.status = MitigationPlan.Status.COMPLETE
        plan.progress = 100
        plan.generated_at = timezone.now()
        plan.save(
            using=db,
            update_fields=["document", "status", "progress", "generated_at"],
        )
        log_action(
            "mitigation_completed",
            f"Mitigation plan generated for analysis run {run.pk} "
            f"({document['summary']['assets']} assets)",
            "mitigationplan",
            plan.pk,
            mode=mode,
            session_id=run.session_id,
        )
        return plan
    except Exception as exc:  # noqa: BLE001 - the plan must be marked failed
        plan.status = MitigationPlan.Status.FAILED
        plan.error = str(exc)
        plan.progress = 0
        plan.save(using=db, update_fields=["status", "error", "progress"])
        log_action(
            "system",
            f"Mitigation plan failed: {exc}",
            "mitigationplan",
            plan.pk,
            mode=mode,
            session_id=run.session_id,
        )
        return plan


def _run_bundle(run, db):
    """Assemble the plain-dict bundle the mitigation agents consume.

    Merges each AssetAssessment (rich CBOM + HNDL + MOSCA artifacts) with the
    run's executive-summary rows so the agent suite sees both the assessment
    verdicts and the raw per-asset evidence.
    """
    exec_summary = run.executive_summary or {}
    rows = exec_summary.get("rows") or []
    row_by_asset = {str(row.get("asset_id")): row for row in rows if row.get("asset_id")}
    risk_ctx = run.risk_context or {}
    repository = run.repository or {}
    target = ""
    scan_job = getattr(run, "scan_job", None)
    if scan_job is not None:
        target = scan_job.target or ""
    risk_app = risk_ctx.get("application") or {}
    app_name = repository.get("name") or risk_app.get("name") or target or "ECDAT inventory"

    assets = []
    assessments = list(run.assessments.all())
    for a in assessments:
        cbom = a.cbom_asset or {}
        cbom_id = str(cbom.get("asset_id") or "")
        fallback_id = str(a.finding_ref or "")
        ex = row_by_asset.get(cbom_id) or row_by_asset.get(fallback_id) or {}
        asset_id = cbom_id or ex.get("asset_id") or fallback_id
        ctx_key = asset_id or f"assessment-{a.pk}"
        assets.append(
            {
                "id": ctx_key,
                "asset_id": asset_id,
                "algorithm": ex.get("algorithm") or cbom.get("algorithm"),
                "family": ex.get("family") or cbom.get("family") or "",
                "algorithm_category": ex.get("algorithm_category")
                or _mosca_field(a, "algorithm_category")
                or "UNKNOWN",
                "classical_security": ex.get("classical_security")
                or _mosca_field(a, "classical_security")
                or "",
                "overall_risk": ex.get("overall_risk")
                or _mosca_field(a, "overall_risk")
                or "",
                "migration_priority": ex.get("migration_priority")
                or _mosca_field(a, "migration_priority")
                or "",
                "quantum_vulnerable": _first_not_none(
                    ex.get("quantum_vulnerable"), _mosca_field(a, "quantum_vulnerable")
                ),
                "hndl_risk": ex.get("hndl_risk") or _hndl_risk(a),
                "cbom_asset": cbom,
                "mosca": a.mosca_result or {},
                "hndl": a.hndl_result or {},
            }
        )

    # A completed run normally has assessments; fall back to the executive
    # summary alone so the plan still renders in degraded states.
    if not assets:
        for ex in rows:
            ctx_key = str(ex.get("asset_id") or "")
            if not ctx_key:
                continue
            assets.append(
                {
                    "id": ctx_key,
                    "asset_id": ctx_key,
                    "algorithm": ex.get("algorithm"),
                    "family": ex.get("family") or "",
                    "algorithm_category": ex.get("algorithm_category") or "UNKNOWN",
                    "classical_security": ex.get("classical_security") or "",
                    "overall_risk": ex.get("overall_risk") or "",
                    "migration_priority": ex.get("migration_priority") or "",
                    "quantum_vulnerable": ex.get("quantum_vulnerable"),
                    "hndl_risk": ex.get("hndl_risk") or "",
                    "cbom_asset": {},
                    "mosca": {},
                    "hndl": {},
                }
            )

    return {
        "application": app_name,
        "repository": repository,
        "risk_context": risk_ctx,
        "assets": assets,
    }


def _mosca_field(assessment, key):
    mosca = (assessment.mosca_result or {}).get("mosca_assessment") or {}
    return mosca.get(key)


def _hndl_risk(assessment):
    hndl = (assessment.hndl_result or {}).get("hndl") or {}
    value = hndl.get("future_decryption_risk")
    if value:
        return value
    if hndl.get("applicable"):
        return hndl.get("risk") or hndl.get("exposure") or ""
    return ""


def _first_not_none(*values):
    for value in values:
        if value is not None:
            return value
    return None


@db_task()
def generate_plan_task(plan_id, mode):
    """Thin huey task wrapper around generate_plan; never crashes the worker."""
    try:
        generate_plan(plan_id, mode)
    except Exception as exc:  # noqa: BLE001 - worker must survive unexpected errors
        logger.exception("generate_plan_task: plan %s (mode=%s) crashed: %s", plan_id, mode, exc)