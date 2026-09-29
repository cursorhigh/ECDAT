"""Authoritative Risk & Urgency Classification Engine for ECDAT.

Provides a single deterministic source of truth for:
- risk_tier: CRITICAL, HIGH, MEDIUM, LOW, NEGLIGIBLE
- priority: URGENT, HIGH, MEDIUM, LOW, NEGLIGIBLE
- urgency_reason: Clear audit rationale explaining the classification
- remediation_wave: Wave 1 (0-3 mo), Wave 2 (3-12 mo), Wave 3 (12-24 mo)
- decision_trace: Step-by-step auditable trace

Downstream components (Analysis, Mitigation Planner, Wave Scheduler, and Report Builder)
consume these results directly.
"""

from typing import Any, Dict, Optional, Tuple


def normalize_algo_name(raw_name: Any) -> str:
    """Normalize algorithm name for consistent comparison."""
    if not raw_name:
        return ""
    if isinstance(raw_name, dict):
        raw_name = raw_name.get("name") or raw_name.get("algorithm") or ""
    return str(raw_name).strip().upper()


def is_shor_vulnerable_primitive(algo: str, family: str) -> bool:
    """Check if algorithm or family is broken by polynomial-time Shor's algorithm on a CRQC."""
    algo_clean = algo.replace("-", "").replace("_", "")
    fam = family.lower()
    return (
        fam in ("rsa", "ecc", "dsa", "dh")
        or any(k in algo_clean for k in ("RSA", "ECC", "ECDSA", "ECDH", "ED25519", "EDDSA", "DSA", "DH", "X25519", "X448"))
    )


def is_classical_weak_primitive(algo: str, family: str) -> bool:
    """Check if algorithm is classically weak/deprecated/broken under NIST SP 800-131A Rev 2."""
    algo_clean = algo.replace("-", "").replace("_", "")
    fam = family.lower()
    return (
        fam in ("des", "3des")
        or any(k in algo_clean for k in ("MD5", "SHA1", "DES", "3DES", "RC4", "RC2", "BLOWFISH"))
    )


def classify_canonical_asset(asset_context: Dict[str, Any]) -> Dict[str, Any]:
    """Authoritative deterministic classifier for cryptographic assets/findings.

    Deterministic Escalation Rules:
    ===============================
    1. URGENT (Priority: URGENT, Risk Tier: CRITICAL, Remediation: Wave 1):
       - Condition A (Classical Critical):
         Classically broken/disallowed primitive (DES, 3DES, RC4, MD5, SHA-1) with exploitability >= 80,
         or explicitly flagged as classical_critical / single DES in active encryption.
       - Condition B (Mosca Deficit + Public/HNDL Exposure):
         Shor-vulnerable asymmetric primitive + active Mosca deficit (X + Y > Z) +
         (public/internet-facing endpoint OR HNDL exposure HIGH/CRITICAL).
       - Condition C (Severe HNDL Intercept):
         Asymmetric / key-establishment primitive + HNDL exposure HIGH/CRITICAL + Shor-vulnerable.

    2. HIGH (Priority: HIGH, Risk Tier: HIGH, Remediation: Wave 2 for PQC, Wave 1 for standard classical):
       - Shor-vulnerable public key primitive without urgent escalation (internal or safe runway).
       - Classically deprecated primitive in standard usage (exploitability < 80).
       - Mosca deficit without public/HNDL urgent escalation.

    3. MEDIUM (Priority: MEDIUM, Risk Tier: MEDIUM, Remediation: Wave 3):
       - 128-bit symmetric ciphers with Grover effective key reduction to 64 bits (e.g. AES-128).
       - Non-standard hashes with collision risks.

    4. LOW (Priority: LOW, Risk Tier: LOW, Remediation: Wave 3 Hardening):
       - Quantum-resilient symmetric encryption (AES-256, AES-256-GCM) providing >= 128 bits post-quantum security.
       - Standard SHA-2 / SHA-3 hashes (SHA-256, SHA-384, SHA-512).
       - Approved Post-Quantum Cryptography (ML-KEM, ML-DSA, SLH-DSA).
    """
    algo = normalize_algo_name(asset_context.get("algorithm") or asset_context.get("name"))
    fam = str(asset_context.get("family") or "").lower()
    params = asset_context.get("parameters") or {}
    key_size = params.get("key_size") or asset_context.get("key_size")

    # Extract role / purpose
    role = str(asset_context.get("role") or asset_context.get("crypto_role") or asset_context.get("purpose") or "").lower()

    # Extract exposure signals
    exposure = str(
        asset_context.get("network_exposure")
        or asset_context.get("exposure")
        or asset_context.get("environment")
        or ""
    ).lower()
    is_public = bool(
        asset_context.get("internet_facing")
        or asset_context.get("public_endpoint")
        or asset_context.get("publicly_accessible")
        or exposure in ("public", "external", "internet")
    )

    # Extract HNDL exposure
    hndl_raw = str(
        asset_context.get("hndl_exposure")
        or asset_context.get("hndl_risk")
        or asset_context.get("future_decryption_risk")
        or ""
    ).upper()

    # Extract Mosca timeline signals
    x_val = asset_context.get("migration_time_years") or asset_context.get("migration_time") or asset_context.get("x_migration_time")
    y_val = asset_context.get("data_shelf_life_years") or asset_context.get("data_shelf_life") or asset_context.get("y_shelf_life")
    z_val = asset_context.get("quantum_horizon_years") or asset_context.get("crqc_horizon") or asset_context.get("z_quantum_horizon")

    x = float(x_val) if x_val is not None and str(x_val).replace(".", "", 1).isdigit() else 2.0
    y = float(y_val) if y_val is not None and str(y_val).replace(".", "", 1).isdigit() else (0.0 if "signature" in role else 5.0)
    z = float(z_val) if z_val is not None and str(z_val).replace(".", "", 1).isdigit() else 7.0

    mosca_deficit = round((x + y) - z, 2)
    mosca_at_risk = bool(
        asset_context.get("mosca_at_risk")
        or (mosca_deficit > 0.0)
        or str(asset_context.get("mosca_status") or "").upper() in ("AT_RISK", "CRITICAL", "EXPIRED", "DEFICIT")
    )

    # Vulnerability properties
    qv = is_shor_vulnerable_primitive(algo, fam)
    classical_weak = is_classical_weak_primitive(algo, fam)
    is_checksum = "checksum" in role or "hash" in role and algo in ("SHA-256", "SHA-384", "SHA-512")
    is_key_est = qv and ("exchange" in role or "establishment" in role or "kem" in role or fam in ("rsa", "dh") or any(k in algo for k in ("RSA", "DH", "ECDH", "X25519", "X448")))

    # Exploitability score
    exploit_score = int(asset_context.get("exploitability_score") or asset_context.get("priority_score") or (95 if "DES" in algo and not "3DES" in algo else (70 if classical_weak else 50)))
    classical_critical = bool(asset_context.get("classical_critical") or (classical_weak and exploit_score >= 80))

    # Evaluate Authoritative Tiers
    risk_tier = "LOW"
    priority = "LOW"
    wave = 3
    urgency_reason = ""
    is_urgent = False

    # --- Condition A: Classical Critical ---
    if classical_weak and (classical_critical or exploit_score >= 80 or ("DES" in algo and not "3DES" in algo)):
        is_urgent = True
        risk_tier = "URGENT"
        priority = "URGENT"
        wave = 1
        urgency_reason = f"Classically broken primitive ({algo}) with critical exploitability ({exploit_score}/100) requires immediate Wave 1 remediation."

    # --- Condition B: Mosca Deficit + Public / HNDL Exposure ---
    elif qv and mosca_at_risk and (is_public or hndl_raw in ("HIGH", "CRITICAL")):
        is_urgent = True
        risk_tier = "URGENT"
        priority = "URGENT"
        wave = 1
        escalation_factor = "public/internet-facing exposure" if is_public else "HIGH HNDL intercept exposure"
        urgency_reason = f"Mosca timeline deficit (X={x}y + Y={y}y > Z={z}y, Deficit: +{mosca_deficit}y) combined with {escalation_factor} requires immediate Wave 1 migration."

    # --- Condition C: Severe HNDL on Key Establishment ---
    elif qv and is_key_est and hndl_raw in ("HIGH", "CRITICAL"):
        is_urgent = True
        risk_tier = "URGENT"
        priority = "URGENT"
        wave = 1
        urgency_reason = f"High Harvest-Now-Decrypt-Later exposure on asymmetric key establishment ({algo}) requires immediate Wave 1 hybridization/migration."

    # --- Standard HIGH (PQC & Classical) ---
    elif qv:
        risk_tier = "HIGH"
        priority = "HIGH"
        wave = 2
        urgency_reason = f"Asymmetric primitive ({algo}) is vulnerable to Shor's algorithm; scheduled for systematic Wave 2 PQC migration."
    elif classical_weak and not is_checksum:
        risk_tier = "HIGH"
        priority = "HIGH"
        wave = 1
        urgency_reason = f"Classically deprecated primitive ({algo}) under NIST SP 800-131A Rev 2; scheduled for Wave 1 replacement."

    # --- MEDIUM ---
    elif "128" in algo or "HMACSHA1" in algo:
        risk_tier = "MEDIUM"
        priority = "MEDIUM"
        wave = 3
        urgency_reason = f"Symmetric primitive ({algo}) subject to Grover effective key-length reduction; scheduled for Wave 3 hardening."

    # --- LOW / PQC / Safe Symmetric ---
    else:
        risk_tier = "LOW"
        priority = "LOW"
        wave = 3
        urgency_reason = f"Primitive ({algo}) maintains post-quantum security margin or is approved PQC; assigned to Wave 3 governance."

    # Build Decision Trace
    decision_trace = {
        "algorithm": algo,
        "role": role or ("Key Establishment" if is_key_est else ("Digital Signature" if qv else "Data Protection")),
        "shor_vulnerable": qv,
        "migration_time_x": x,
        "shelf_life_y": y,
        "horizon_z": z,
        "mosca_sum_xy": round(x + y, 2),
        "mosca_deficit": mosca_deficit,
        "mosca_at_risk": mosca_at_risk,
        "public_exposure": is_public,
        "hndl_exposure": hndl_raw or ("HIGH" if is_public and is_key_est else "NOT_ASSESSABLE"),
        "urgent_escalation": is_urgent,
        "final_risk_tier": risk_tier,
        "final_priority": priority,
        "remediation_wave": wave,
        "urgency_reason": urgency_reason,
    }

    return {
        "risk_tier": risk_tier,
        "priority": priority,
        "remediation_wave": wave,
        "urgency_reason": urgency_reason,
        "decision_trace": decision_trace,
        "quantum_vulnerable": qv,
        "classical_security": "WEAK" if classical_weak else "STRONG",
        "mosca_deficit": mosca_deficit,
        "mosca_at_risk": mosca_at_risk,
        "is_public": is_public,
        "hndl_exposure": hndl_raw or ("HIGH" if is_public and is_key_est else "NOT_ASSESSABLE"),
    }
