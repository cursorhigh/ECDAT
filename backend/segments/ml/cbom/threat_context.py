"""Unified Threat Context — Single source of truth for Mosca / HNDL / Priority.

Phase C: Defines a ThreatContext that is resolved once and passed to every
analysis stage. Handles parameter conflicts explicitly and documents defaults.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ThreatContext:
    """Single source of truth for all threat-modeling parameters.

    Resolved once at the start of an analysis run and passed to every stage
    (Mosca solver, HNDL agent, risk classifier, mitigation planner, report).
    """
    # Mosca parameters
    migration_years_x: float = 3.0
    data_shelf_life_y: float = 8.0
    crqc_year_z: int = 2033
    assessment_year: int = 2026

    # Network / exposure context
    network_exposure: str = "internal"  # "public", "external", "internal", "isolated"
    internet_facing: bool = False

    # Data context
    data_sensitivity: Optional[str] = None  # "high", "medium", "low", None
    data_types: List[str] = field(default_factory=list)

    # Standards profile: "nist_general" or "cnsa_2_0"
    standards_profile: str = "nist_general"

    # Track which parameters were explicitly provided vs defaulted
    defaulted_params: List[str] = field(default_factory=list)
    conflict_warnings: List[str] = field(default_factory=list)

    # Whether we have enough information for HNDL assessment
    hndl_assessable: bool = False

    @property
    def years_until_crqc(self) -> float:
        """Z in years (not a calendar year)."""
        return max(0.0, float(self.crqc_year_z - self.assessment_year))

    @property
    def mosca_deficit(self) -> float:
        """Delta_M = (X + Y) - Z. Positive means migration won't complete before CRQC."""
        return (self.migration_years_x + self.data_shelf_life_y) - self.years_until_crqc

    @property
    def mosca_at_risk(self) -> bool:
        """True if X + Y > Z (Mosca inequality violated)."""
        return self.mosca_deficit > 0.0

    @property
    def migration_deadline_year(self) -> int:
        """Year by which migration must START to finish before CRQC."""
        return int(self.crqc_year_z - self.migration_years_x)

    def check_hndl_assessability(self) -> tuple[bool, str]:
        """Determine if we have sufficient inputs for HNDL assessment.

        Returns (is_assessable, reason).
        """
        missing = []
        if self.data_sensitivity is None:
            missing.append("data_sensitivity")
        if not self.data_types:
            missing.append("data_types")
        if "data_shelf_life_y" in self.defaulted_params:
            missing.append("data_shelf_life (using default)")

        if missing:
            self.hndl_assessable = False
            return False, f"Missing inputs for HNDL: {', '.join(missing)}"

        self.hndl_assessable = True
        return True, "All required HNDL inputs present"


def resolve_threat_context(
    run_parameters: Optional[Dict[str, Any]] = None,
    digital_twin: Optional[Dict[str, Any]] = None,
    user_overrides: Optional[Dict[str, Any]] = None,
) -> ThreatContext:
    """Resolve a ThreatContext from multiple parameter sources.

    Priority: user_overrides > run_parameters > digital_twin > defaults.
    Conflicts between sources are logged as warnings and the more conservative
    value is used unless overridden.
    """
    params = run_parameters or {}
    twin = digital_twin or {}
    overrides = user_overrides or {}

    ctx = ThreatContext()
    defaulted = []

    # Migration time X
    if "migration_years" in overrides:
        ctx.migration_years_x = float(overrides["migration_years"])
    elif "migration_time_years" in params:
        ctx.migration_years_x = float(params["migration_time_years"])
    elif "migration_time" in twin:
        ctx.migration_years_x = float(twin["migration_time"])
    else:
        defaulted.append("migration_years_x")

    # Data shelf-life Y
    if "data_shelf_life" in overrides:
        ctx.data_shelf_life_y = float(overrides["data_shelf_life"])
    elif "data_shelf_life_years" in params:
        ctx.data_shelf_life_y = float(params["data_shelf_life_years"])
    elif "data_lifetime" in twin:
        ctx.data_shelf_life_y = float(twin["data_lifetime"])
    else:
        defaulted.append("data_shelf_life_y")

    # CRQC year Z
    if "crqc_year" in overrides:
        ctx.crqc_year_z = int(overrides["crqc_year"])
    elif "quantum_horizon_year" in params:
        ctx.crqc_year_z = int(params["quantum_horizon_year"])
    else:
        defaulted.append("crqc_year_z")

    # Assessment year
    if "assessment_year" in overrides:
        ctx.assessment_year = int(overrides["assessment_year"])
    elif "assessment_year" in params:
        ctx.assessment_year = int(params["assessment_year"])
    else:
        defaulted.append("assessment_year")

    # Network exposure — use most conservative value on conflict
    run_exposure = params.get("network_exposure") or ""
    twin_exposure = (twin.get("contexts") or {}).get("exposure") or ""
    override_exposure = overrides.get("network_exposure") or ""

    exposure_rank = {"public": 0, "external": 1, "internal": 2, "isolated": 3}

    if override_exposure:
        ctx.network_exposure = override_exposure
    elif run_exposure and twin_exposure and run_exposure != twin_exposure:
        # Conflict: use the more conservative (lower rank = more exposed)
        run_rank = exposure_rank.get(run_exposure, 2)
        twin_rank = exposure_rank.get(twin_exposure, 2)
        if run_rank < twin_rank:
            ctx.network_exposure = run_exposure
            ctx.conflict_warnings.append(
                f"Network exposure conflict: run says '{run_exposure}', "
                f"digital twin says '{twin_exposure}'. Using more conservative: '{run_exposure}'."
            )
        else:
            ctx.network_exposure = twin_exposure
            ctx.conflict_warnings.append(
                f"Network exposure conflict: run says '{run_exposure}', "
                f"digital twin says '{twin_exposure}'. Using more conservative: '{twin_exposure}'."
            )
    elif run_exposure:
        ctx.network_exposure = run_exposure
    elif twin_exposure:
        ctx.network_exposure = twin_exposure
    else:
        defaulted.append("network_exposure")

    ctx.internet_facing = ctx.network_exposure in ("public", "external")

    # Data context
    ctx.data_sensitivity = overrides.get("data_sensitivity") or params.get("data_sensitivity")
    ctx.data_types = overrides.get("data_types") or params.get("data_types") or []

    # Standards profile
    ctx.standards_profile = overrides.get("standards_profile") or params.get("standards_profile") or "nist_general"

    ctx.defaulted_params = defaulted

    # Log conflicts
    for w in ctx.conflict_warnings:
        logger.warning("[THREAT_CONTEXT] %s", w)
    if defaulted:
        logger.info("[THREAT_CONTEXT] Defaulted parameters: %s", ", ".join(defaulted))

    # Check HNDL assessability
    ctx.check_hndl_assessability()

    return ctx


# ---------------------------------------------------------------------------
# Invariant checks (Phase C.5)
# ---------------------------------------------------------------------------

class AnalysisInvariantError(Exception):
    """Raised when post-analysis invariant checks fail."""
    pass


def validate_analysis_invariants(
    assets: List[Dict[str, Any]],
    threat_ctx: ThreatContext,
    summary_counts: Dict[str, int],
    table_counts: Dict[str, int],
    strict: bool = False,
) -> List[str]:
    """Validate internal consistency after analysis.

    Returns a list of warning strings. If `strict` is True, raises
    AnalysisInvariantError on the first failure instead of collecting.

    Checks:
    1. If Mosca says At Risk, at least one urgent/critical/HNDL count must be > 0
    2. Any weak-classified asset must have priority >= MEDIUM
    3. Summary text counts must match table counts
    4. Classical-weak security-use assets must be >= MEDIUM priority
    """
    warnings = []

    def _warn(msg: str):
        warnings.append(msg)
        if strict:
            raise AnalysisInvariantError(msg)

    # 1. Mosca At Risk consistency
    if threat_ctx.mosca_at_risk:
        urgent = sum(1 for a in assets if str(a.get("priority", "")).upper() in ("URGENT", "CRITICAL"))
        hndl_exposed = sum(1 for a in assets if str(a.get("hndl_risk", "")).upper() in ("HIGH", "CRITICAL"))
        shor_vuln = sum(1 for a in assets if a.get("quantum_vulnerable") or a.get("is_shor_vulnerable"))
        if urgent == 0 and hndl_exposed == 0 and shor_vuln > 0:
            _warn(
                f"Mosca inequality violated (X+Y={threat_ctx.migration_years_x + threat_ctx.data_shelf_life_y} > "
                f"Z={threat_ctx.years_until_crqc}) with {shor_vuln} Shor-vulnerable asset(s), but "
                f"urgent/critical count is 0 and HNDL-exposed count is 0."
            )

    # 2. Weak-classified assets must have priority >= MEDIUM
    priority_rank = {"URGENT": 0, "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for a in assets:
        risk = str(a.get("risk_key", "")).lower()
        pri = str(a.get("priority", "")).upper()
        if risk == "weak" and priority_rank.get(pri, 99) > 2:
            _warn(
                f"Asset '{a.get('name', 'unknown')}' classified as weak but has priority "
                f"{pri} (below MEDIUM). Weak security-use crypto must be >= MEDIUM priority."
            )

    # 3. Summary vs table count agreement
    for key in ("vulnerable", "weak", "moderate", "pqc", "unknown"):
        s_count = summary_counts.get(key, 0)
        t_count = table_counts.get(key, 0)
        if s_count != t_count:
            _warn(
                f"Summary count for '{key}' ({s_count}) disagrees with "
                f"table count ({t_count})."
            )

    # 4. Total assets consistency
    total_summary = sum(summary_counts.get(k, 0) for k in ("vulnerable", "weak", "moderate", "pqc", "unknown"))
    total_table = sum(table_counts.get(k, 0) for k in ("vulnerable", "weak", "moderate", "pqc", "unknown"))
    if total_summary != total_table:
        _warn(
            f"Total canonical assets from summary ({total_summary}) disagrees "
            f"with total from table ({total_table})."
        )

    return warnings
