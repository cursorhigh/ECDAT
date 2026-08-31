"""Deterministic mitigation rule engines.

Each agent runs rules against a single asset context combined with a run
bundle (service usage, exposure, risk context). Together they predict blast
radius, migration impact and produce actionable suggestions without needing
an LLM -- the LLM (NarratorAgent) only polishes narrative prose when a key
is available.

All helpers are pure and unit-testable with plain dicts.
"""

import posixpath
from typing import Any, Dict, List, Optional

PRIORITY_RANK = {"URGENT": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
RISK_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def normalize_algorithm(raw: Any) -> str:
    """Return an uppercase canonical algorithm token from CBOM output."""
    if isinstance(raw, dict):
        raw = raw.get("name", "")
    return str(raw or "").strip().upper()


def service_for_location(file_path: Optional[str]) -> str:
    """Derive the logical service/context for a CBOM asset location.

    Handles both POSIX and Windows paths: prefers an ``apps/<service>``
    segment, then ``<repo>/<service>`` nesting, then the parent directory
    of the file, and finally a stable ``unknown`` string.
    """
    if not file_path:
        return "unknown"
    parts = posixpath.normpath(str(file_path).replace("\\", "/")).split("/")
    parts = [p for p in parts if p]
    if not parts:
        return "unknown"
    for idx, part in enumerate(parts):
        if part.lower() in ("apps", "app", "src", "source", "services", "modules"):
            if idx + 1 < len(parts):
                return parts[idx + 1] or "unknown"
    filename = parts[-1]
    if len(parts) >= 2 and "." in filename:
        return parts[-2] or "unknown"
    return "unknown"


def service_for_asset(asset_ctx: Dict[str, Any]) -> str:
    cbom = asset_ctx.get("cbom_asset") or {}
    location = cbom.get("location") or {}
    return service_for_location(location.get("file"))


def exposure_for(run_bundle: Dict[str, Any]) -> str:
    """Collapse risk-context network flags into public/internal/isolated."""
    risk = run_bundle.get("risk_context") or {}
    network = risk.get("network") or {}
    if network.get("publicly_accessible") or network.get("internet_facing"):
        return "public"
    if network.get("external_users"):
        return "external"
    return "internal"


# ---------------------------------------------------------------------------
# BlastRadiusAgent
# ---------------------------------------------------------------------------


def _base_severity(asset_ctx: Dict[str, Any]) -> str:
    priority = asset_ctx.get("migration_priority") or "MEDIUM"
    return {
        "URGENT": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
    }.get(priority.upper(), "MEDIUM")


def compute_blast_radius(asset_ctx: Dict[str, Any], run_bundle: Dict[str, Any]) -> Dict[str, Any]:
    """Predict how far a cryptographic failure reaches for one asset."""
    category = (asset_ctx.get("algorithm_category") or "UNKNOWN").upper()
    qv = bool(asset_ctx.get("quantum_vulnerable"))
    priority = (asset_ctx.get("migration_priority") or "MEDIUM").upper()
    service = asset_ctx.get("service") or service_for_asset(asset_ctx)
    exposure = exposure_for(run_bundle)
    shared = sum(
        1
        for other in run_bundle.get("assets") or []
        if other.get("id") != asset_ctx.get("id")
        and (other.get("service") or service_for_asset(other)) == service
    )

    severity = _base_severity(asset_ctx)
    if category == "PUBLIC_KEY" and qv:
        # A CRQC can break these outright (Shor), not just weaken them.
        severity = "CRITICAL" if priority in ("URGENT", "HIGH") else "HIGH"
    if exposure == "public" and severity == "MEDIUM":
        severity = "HIGH"
    if category == "HASH" and asset_ctx.get("algorithm") and str(asset_ctx.get("algorithm")).upper() in ("MD5", "SHA1"):
        severity = "MEDIUM"

    reason = (
        f"{asset_ctx.get('algorithm') or 'Unknown'} in '{service}' exposes "
        f"{shared + 1} crypto asset(s); surface is {exposure}."
    )
    if category == "PUBLIC_KEY" and qv:
        reason = (
            f"{asset_ctx.get('algorithm') or 'Unknown'} is post-quantum vulnerable "
            f"(Shor) and lives in '{service}' ({exposure} surface); compromise breaks "
            f"confidentiality and integrity for {shared + 1} trust chain member(s)."
        )
    return {
        "severity": severity,
        "severity_rank": SEVERITY_RANK.get(severity, 3),
        "service": service,
        "exposure": exposure,
        "shared_assets": shared + 1,
        "services_affected": [service],
        "reason": reason,
    }


# ---------------------------------------------------------------------------
# MigrationImpactAgent
# ---------------------------------------------------------------------------

_REPLACEMENTS = {
    # (canonical algo) -> (replacement, category, effort, impact, compatibility_risk, reason)
    "RSA": (
        "ML-KEM-1024 / ML-DSA-87",
        "PUBLIC_KEY",
        "HIGH",
        "HIGH",
        "HIGH",
        "RSA is used across TLS, JWTs and certificates; each trust anchor must move to ML-KEM/ML-DSA.",
    ),
    "ECDSA": (
        "ML-DSA-65",
        "PUBLIC_KEY",
        "MEDIUM",
        "MEDIUM",
        "MEDIUM",
        "ECDSA signatures migrate cleanly to ML-DSA; verify curve usage first.",
    ),
    "ECDH": (
        "ML-KEM-1024",
        "PUBLIC_KEY",
        "MEDIUM",
        "MEDIUM",
        "MEDIUM",
        "Key agreement migrates to ML-KEM with a hybrid handshake (X25519MLKEM768).",
    ),
    "EC": (
        "ML-KEM-1024 / ML-DSA-65",
        "PUBLIC_KEY",
        "MEDIUM",
        "MEDIUM",
        "MEDIUM",
        "Elliptic-curve assets can move to ML-KEM/ML-DSA per CNSA 2.0.",
    ),
    "ED25519": (
        "ML-DSA-65",
        "PUBLIC_KEY",
        "MEDIUM",
        "MEDIUM",
        "MEDIUM",
        "Ed25519 signatures migrate to ML-DSA; keep graceful fallback while pubkeys rotate.",
    ),
    "EDDSA": (
        "ML-DSA-65",
        "PUBLIC_KEY",
        "MEDIUM",
        "MEDIUM",
        "MEDIUM",
        "EdDSA signatures migrate to ML-DSA per CNSA 2.0.",
    ),
    "DSA": (
        "ML-KEM-1024 / ML-DSA-87",
        "PUBLIC_KEY",
        "HIGH",
        "HIGH",
        "HIGH",
        "DSA is baroque and PQC-weak; replace with ML-KEM/ML-DSA.",
    ),
    "DH": (
        "ML-KEM-1024",
        "PUBLIC_KEY",
        "HIGH",
        "HIGH",
        "HIGH",
        "Diffie-Hellman key exchange moves to ML-KEM.",
    ),
    "ELGAMAL": (
        "ML-KEM-1024",
        "PUBLIC_KEY",
        "HIGH",
        "HIGH",
        "HIGH",
        "ElGamal encryption migrates to ML-KEM encapsulation.",
    ),
    "AES": (
        "AES-256 (GCM)",
        "SYMMETRIC",
        "LOW",
        "LOW",
        "LOW",
        "AES-256 is quantum-resilient (Grover safety margin); validate GCM mode.",
    ),
    "DES": (
        "AES-256 (GCM)",
        "SYMMETRIC",
        "MEDIUM",
        "MEDIUM",
        "MEDIUM",
        "DES/3DES is legacy; migrate to AES-256.",
    ),
    "3DES": (
        "AES-256 (GCM)",
        "SYMMETRIC",
        "MEDIUM",
        "MEDIUM",
        "MEDIUM",
        "3DES is legacy; migrate to AES-256.",
    ),
    "BLOWFISH": (
        "AES-256 (GCM)",
        "SYMMETRIC",
        "MEDIUM",
        "MEDIUM",
        "MEDIUM",
        "Blowfish is legacy; migrate to AES-256.",
    ),
    "RC4": (
        "AES-256 (GCM)",
        "SYMMETRIC",
        "MEDIUM",
        "MEDIUM",
        "MEDIUM",
        "RC4 is broken; migrate to AES-256.",
    ),
    "CAMELLIA": (
        "AES-256 (GCM)",
        "SYMMETRIC",
        "MEDIUM",
        "MEDIUM",
        "MEDIUM",
        "Camellia is acceptable; consolidate on AES-256 where possible.",
    ),
    "SHA1": (
        "SHA-256 / SHA-3",
        "HASH",
        "LOW",
        "LOW",
        "MEDIUM",
        "SHA-1 has known collision attacks; move to SHA-256/SHA-3.",
    ),
    "MD5": (
        "SHA-256 / SHA-3",
        "HASH",
        "LOW",
        "LOW",
        "HIGH",
        "MD5 is fully broken; move to SHA-256/SHA-3.",
    ),
    "SHA256": (
        "SHA-256 / SHA-3",
        "HASH",
        "LOW",
        "LOW",
        "LOW",
        "SHA-256 is quantum-safe at the Grover bound; confirm context use.",
    ),
    "SHA512": (
        "SHA-256 / SHA-3",
        "HASH",
        "LOW",
        "LOW",
        "LOW",
        "SHA-512 is quantum-safe; confirm context use.",
    ),
    "SHA3": (
        "SHA-3",
        "HASH",
        "LOW",
        "LOW",
        "LOW",
        "SHA-3 is quantum-safe; no action required.",
    ),
    "HMAC": (
        "HMAC-SHA-256 / HMAC-SHA3",
        "HASH",
        "LOW",
        "LOW",
        "LOW",
        "HMAC is quantum-safe keyed hashing; rotate keys on schedule.",
    ),
}

_UNKNOWN_REPLACEMENT = (
    "Review & standards triage",
    "UNKNOWN",
    "MEDIUM",
    "MEDIUM",
    "MEDIUM",
    "Unrecognized or custom crypto requires a standards-compliance review.",
)


def compute_migration_impact(asset_ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Predict the effort, compatibility risk and PQC replacement for an asset."""
    algo = normalize_algorithm(asset_ctx.get("algorithm"))
    family = str(asset_ctx.get("family") or "").upper()

    lookup = algo
    if lookup not in _REPLACEMENTS:
        lookup = family
    if lookup not in _REPLACEMENTS:
        lookup = algo.split()[0] if algo else ""
    if lookup not in _REPLACEMENTS:
        lookup = ""

    replacement, category, effort, impact, compat, reason = _REPLACEMENTS.get(
        lookup, _UNKNOWN_REPLACEMENT
    )

    # The deterministic MOSCA assessment overrides the generic estimate when
    # it classified the asset clearly.
    category_override = asset_ctx.get("algorithm_category") or category
    if algo and category_override == "SYMMETRIC" and algo == "AES":
        params = (asset_ctx.get("cbom_asset") or {}).get("parameters") or {}
        key_size = params.get("key_size")
        if key_size is not None and str(key_size).isdigit() and int(key_size) < 256:
            effort, impact, compat = "MEDIUM", "MEDIUM", "MEDIUM"
            reason = "AES key size below 256 bits; raise to AES-256 and validate mode."

    return {
        "replacement": replacement,
        "replacement_category": category_override,
        "effort": effort,
        "impact": impact,
        "compatibility_risk": compat,
        "reason": reason,
    }


def migration_wave_for(asset_ctx: Dict[str, Any], blast: Dict[str, Any]) -> int:
    """Assign assets to a migration wave (1 = stop-the-bleeding first)."""
    priority = (asset_ctx.get("migration_priority") or "MEDIUM").upper()
    category = (asset_ctx.get("algorithm_category") or "").upper()
    qv = bool(asset_ctx.get("quantum_vulnerable"))
    severity = blast.get("severity", "MEDIUM")
    if priority == "URGENT" or severity == "CRITICAL" or (category == "PUBLIC_KEY" and qv):
        return 1
    if priority == "HIGH" or severity == "HIGH" or category == "PUBLIC_KEY":
        return 2
    return 3


# ---------------------------------------------------------------------------
# SuggestionAgent
# ---------------------------------------------------------------------------


def suggestions_for(asset_ctx: Dict[str, Any], blast: Dict[str, Any], impact: Dict[str, Any]) -> List[str]:
    """Return a short, ordered list of actionable next steps for one asset."""
    algo = normalize_algorithm(asset_ctx.get("algorithm")) or "Unknown"
    category = (asset_ctx.get("algorithm_category") or "UNKNOWN").upper()
    qv = bool(asset_ctx.get("quantum_vulnerable"))
    priority = (asset_ctx.get("migration_priority") or "").upper()
    service = blast.get("service", "unknown")
    replacement = impact.get("replacement", "")
    hndl = asset_ctx.get("hndl_risk") or ""

    out: List[str] = []
    if category == "PUBLIC_KEY":
        out.append(
            f"Replace {algo} with {replacement} (CNSA 2.0 / NIST PQC) in '{service}'."
        )
        out.append(
            "Adopt hybrid key exchange (X25519MLKEM768) so TLS and message-level "
            "handshakes are HNDL-safe today."
        )
        if hndl:
            out.append(
                f"Rotate {algo} keys/certificates in '{service}' now - harvest-now "
                f"decrypt-later exposure: {hndl}."
            )
        elif qv:
            out.append(
                "Classify all data protected by {algo} keys and rotate anything "
                "long-lived to a PQC scheme.".replace("{algo}", algo)
            )
    elif category == "SYMMETRIC":
        out.append(
            f"Maintain {algo} with AES-256 strength; re-validate the cipher mode and "
            "key-management rotation in '{service}'."
        )
        out.append("Ensure symmetric keys are rotated on schedule and stored in a KMS.")
    elif category == "HASH":
        out.append(
            f"Strengthen {algo} usage to SHA-256/SHA-3 for integrity and signing contexts in '{service}'."
        )
        out.append("Remove {algo} from security-sensitive signature paths.".replace("{algo}", algo))
    else:
        out.append(
            f"Triage the {algo} reference in '{service}' for standards compliance."
        )
        out.append("Add a crypto policy guard: only approved suites may ship.")

    if priority == "URGENT":
        out.append("Treat as a Week-0 item: raise a change ticket and assign an owner.")
    elif priority == "HIGH":
        out.append("Schedule within the current migration quarter; assign an owner.")

    return out[:4]


def recommended_action_for(asset_ctx: Dict[str, Any]) -> str:
    mosca = asset_ctx.get("mosca") or {}
    assessment = mosca.get("mosca_assessment") or {}
    action = assessment.get("recommended_action")
    if action:
        return action
    priority = (asset_ctx.get("migration_priority") or "").upper()
    if priority == "URGENT":
        return "Prioritize a structured migration plan toward appropriate post-quantum mechanisms."
    if priority == "HIGH":
        return "Schedule replacement within the current migration window."
    if priority == "MEDIUM":
        return "Plan replacement during the next major release."
    return "Monitor and maintain current deployment with sound key management."


# ---------------------------------------------------------------------------
# Plan-level helpers
# ---------------------------------------------------------------------------


def digital_twin(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """Build the abstract 'digital twin' view of the crypto estate."""
    assets = bundle.get("assets") or []
    services: Dict[str, int] = {}
    algorithm_counts: Dict[str, int] = {}
    algorithm_services: Dict[str, List[str]] = {}
    for asset in assets:
        service = asset.get("service") or service_for_asset(asset)
        services[service] = services.get(service, 0) + 1
        algo = normalize_algorithm(asset.get("algorithm")) or "Unknown"
        algorithm_counts[algo] = algorithm_counts.get(algo, 0) + 1
        algorithm_services.setdefault(algo, [])
        if service not in algorithm_services[algo]:
            algorithm_services[algo].append(service)

    abstractions = []
    for algo in sorted(algorithm_counts, key=lambda a: -algorithm_counts[a]):
        abstractions.append(
            {
                "type": "algorithm",
                "label": algo,
                "count": algorithm_counts[algo],
                "contexts": algorithm_services[algo],
                "roles": _roles_for(algo),
            }
        )

    risk = bundle.get("risk_context") or {}
    network = risk.get("network") or {}
    data = risk.get("data") or {}
    return {
        "abstractions": abstractions,
        "contexts": {
            "services": sorted(services),
            "applications": [bundle.get("application") or "ECDAT inventory"],
            "exposure": exposure_for(bundle),
            "data_types": data.get("types") or [],
            "publicly_accessible": bool(network.get("publicly_accessible") or network.get("internet_facing")),
        },
        "high_value_points": [
            {
                "label": f"Service '{s}'",
                "reason": f"concentrates {c} cryptographic asset(s) in one blast zone",
            }
            for s, c in sorted(services.items(), key=lambda kv: -kv[1])[:4]
        ],
    }


def _roles_for(algo: str) -> List[str]:
    if algo in ("RSA", "ECDSA", "ED25519", "EDDSA", "DSA"):
        return ["digital_signature", "authentication", "certificates"]
    if algo in ("ECDH", "DH", "ELGAMAL"):
        return ["key_exchange", "transport_security"]
    if algo in ("AES", "DES", "3DES", "BLOWFISH", "RC4", "CAMELLIA"):
        return ["confidentiality", "data_encryption"]
    if algo.startswith("SHA") or algo == "MD5":
        return ["integrity", "message_digest"]
    if algo == "HMAC":
        return ["keyed_integrity", "message_authentication"]
    return ["cryptographic_primitives"]


def quantum_risk(bundle: Dict[str, Any]) -> Dict[str, Any]:
    assets = bundle.get("assets") or []
    vulnerable = [
        {
            "asset_id": a.get("id"),
            "algorithm": normalize_algorithm(a.get("algorithm")) or "Unknown",
            "service": a.get("service") or service_for_asset(a),
            "priority": a.get("migration_priority"),
        }
        for a in assets
        if a.get("quantum_vulnerable")
    ]
    hndl_high = sum(
        1 for a in assets if str(a.get("hndl_risk") or "").upper() in ("HIGH", "CRITICAL")
    )
    return {
        "post_quantum_vulnerable": vulnerable,
        "hndl_present": hndl_high > 0,
        "harvest_now_decrypt_later": hndl_high > 0,
        "rationale": (
            "Public-key primitives (RSA, ECC) are vulnerable to Shor's algorithm on a "
            "future cryptographically-relevant quantum computer (CRQC). Ciphertext "
            "captured today can be decrypted later (Harvest-Now-Decrypt-Later), and "
            "long-lived signatures forged - which is why PQC migration is time-critical."
        ),
        "urgency": "Wave 1" if vulnerable else "Wave 3",
    }


def blast_radius_summary(bundle: Dict[str, Any]) -> Dict[str, Any]:
    assets = bundle.get("assets") or []
    severities = [a.get("blast", {}).get("severity", "LOW") for a in assets]
    worst = "LOW"
    if severities:
        worst = min(severities, key=lambda s: SEVERITY_RANK.get(s, 3))
    per_algo: Dict[str, Dict[str, Any]] = {}
    for a in assets:
        algo = normalize_algorithm(a.get("algorithm")) or "Unknown"
        sev = a.get("blast", {}).get("severity", "LOW")
        entry = per_algo.setdefault(algo, {"count": 0, "severity": sev})
        entry["count"] += 1
        if SEVERITY_RANK.get(sev, 3) < SEVERITY_RANK.get(entry["severity"], 3):
            entry["severity"] = sev
    services = {a.get("service") or service_for_asset(a) for a in assets}
    return {
        "severity": worst,
        "affected_services": len(services),
        "affected_findings": len(assets),
        "public_surface": exposure_for(bundle) == "public",
        "per_algorithm": [
            {"algorithm": algo, "count": entry["count"], "severity": entry["severity"]}
            for algo, entry in sorted(per_algo.items(), key=lambda kv: SEVERITY_RANK.get(kv[1]["severity"], 3))
        ],
        "poorest_link": worst,
    }


WAVE_DEFS = [
    {
        "name": "Wave 1 - Stop the bleeding (HNDL & PQC triage)",
        "timeline": "0-3 months",
        "focus": (
            "Rotate HNDL-exposed keys, add hybrid handshakes and stage urgent "
            "post-quantum replacements for publicly exposed primitives."
        ),
    },
    {
        "name": "Wave 2 - Post-quantum migration",
        "timeline": "3-12 months",
        "focus": (
            "Systematically move public-key signatures and key exchange to ML-KEM / "
            "ML-DSA per CNSA 2.0, covering downstream trust chains."
        ),
    },
    {
        "name": "Wave 3 - Hardening & governance",
        "timeline": "12-24 months",
        "focus": (
            "Consolidate symmetric modes (AES-256), strengthen hashes to SHA-3, retire "
            "legacy ciphers and codify crypto policy so new failures cannot ship."
        ),
    },
]


def baseline_recommendations(bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    assets = bundle.get("assets") or []
    urgent = sum(1 for a in assets if (a.get("migration_priority") or "").upper() == "URGENT")
    qv = sum(1 for a in assets if a.get("quantum_vulnerable"))
    hndl = sum(1 for a in assets if (a.get("hndl_risk") or "").upper() in ("HIGH", "CRITICAL"))
    exposure = exposure_for(bundle)

    recs = [
        {
            "priority": "HIGH",
            "wave": 1,
            "title": "HNDL exposure cut & key rotation",
            "description": (
                f"{hndl} asset(s) face harvest-now-decrypt-later exposure. Rotate "
                "affected keys/certificates and introduce hybrid TLS handshakes before "
                "any large-scale PQC migration."
            ),
            "actions": ["Rotate HNDL-exposed keys & certs", "Enable X25519MLKEM768 hybrid handshake"],
        },
        {
            "priority": "HIGH",
            "wave": 1,
            "title": "Urgent post-quantum replacements",
            "description": (
                f"{urgent} asset(s) are URGENT priority and {qv} are post-quantum "
                f"vulnerable on a {exposure} surface. Stage ML-KEM/ML-DSA pilots in "
                "the most exposed services first."
            ),
            "actions": ["Pilot ML-KEM/ML-DSA in exposed services", "Certify trust chains against CNSA 2.0"],
        },
        {
            "priority": "MEDIUM",
            "wave": 2,
            "title": "Broad public-key migration",
            "description": (
                "Migrate all remaining RSA/ECC primitives to NIST PQC within the next "
                "two quarters, with graceful fallback while certificates rotate."
            ),
            "actions": ["Schedule RSA/ECC -> ML-KEM/ML-DSA migration", "Update libraries & SDKs"],
        },
        {
            "priority": "MEDIUM",
            "wave": 3,
            "title": "Symmetric & digest hardening",
            "description": (
                "Consolidate data-at-rest to AES-256 GCM and strengthen hashes to "
                "SHA-256/SHA-3; retire DES/3DES/MD5/SHA-1 references."
            ),
            "actions": ["AES-256 GCM enforcement", "SHA-3 digest adoption", "Retire legacy ciphers"],
        },
        {
            "priority": "MEDIUM",
            "wave": 3,
            "title": "Crypto governance & policy",
            "description": (
                "Codify an approved-cryptography policy and wire CBOM-driven guardrails "
                "into CI so new disallowed primitives fail the build."
            ),
            "actions": ["Publish approved algorithms policy", "CBOM guardrail in CI", "Quarterly crypto audit"],
        },
    ]
    return recs