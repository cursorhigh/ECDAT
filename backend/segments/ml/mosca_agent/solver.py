"""
MOSCA+ Inequality Mathematical Solver (solver.py)

Implements Michele Mosca's Theorem of Quantum Risk (X + Y > Z) as a pure,
reproducible deterministic mathematical and timeline engine:
- X: Migration Time (years)
- Y: Data Shelf Life / Confidentiality Requirement (years)
- Z: Time to CRQC / Quantum Threat Horizon (years)
- Delta M: Mosca Deficit / Safety Margin (years)
- T_deadline: Migration Start Deadline Year
- R_mosca: Normalized Mosca Risk Index (0.0 to 1.0)
"""

from typing import Dict, Any, Optional, Tuple, Literal, Union
from segments.ml.cbom.crypto_catalog import lookup_crypto_algorithm


class MoscaSolver:
    """
    Deterministic mathematical engine for solving Mosca's quantum risk inequality.
    """

    DEFAULT_QUANTUM_HORIZON_YEAR = 2033
    DEFAULT_ASSESSMENT_YEAR = 2026

    # Complexity baseline migration durations (in years)
    COMPLEXITY_MAP = {
        1: 0.5,  # Trivial
        2: 1.0,  # Low
        3: 2.0,  # Moderate
        4: 3.5,  # High
        5: 5.0,  # Extreme
    }

    @classmethod
    def derive_migration_time(
        cls,
        migration_time_years: Optional[Union[float, int]] = None,
        crypto_agility: int = 3,
        migration_complexity: int = 3,
        dependency_count: int = 0,
        hardware_dependency: bool = False,
    ) -> float:
        """
        Derives or validates migration time X (in years) deterministically.
        """
        if migration_time_years is not None:
            try:
                val = float(migration_time_years)
                if val >= 0.0:
                    return round(val, 2)
            except (ValueError, TypeError):
                pass

        # Derive X from agility, complexity, and dependencies
        comp = max(1, min(5, int(migration_complexity)))
        agility = max(1, min(5, int(crypto_agility)))

        base_x = cls.COMPLEXITY_MAP.get(comp, 2.0)
        
        # Agility modifier: lower agility (hardcoded keys) increases migration time
        agility_mod = (5 - agility) * 0.40  # agility 5 -> +0.0, agility 1 -> +1.6 yrs
        
        # Hardware dependency modifier
        hw_mod = 1.0 if hardware_dependency else 0.0

        # Dependency chain modifier
        dep_mod = 0.5 if dependency_count > 20 else (0.2 if dependency_count > 5 else 0.0)

        derived_x = base_x + agility_mod + hw_mod + dep_mod
        return round(min(15.0, max(0.1, derived_x)), 2)

    @classmethod
    def calculate_crypto_susceptibility(
        cls,
        algorithm_name: Optional[str],
        family: Optional[str] = None,
        crypto_role: Optional[str] = None,
        key_size: Optional[int] = None,
        curve: Optional[str] = None,
    ) -> Tuple[float, bool]:
        """
        Calculates cryptographic susceptibility S_crypto in [0.0, 1.0].
        """
        algo_str = str(algorithm_name or "").strip()
        fam_str = str(family or "").lower().strip()
        role_str = str(crypto_role or "").lower().strip()

        catalog_entry = lookup_crypto_algorithm(algo_str, key_size=key_size, curve=curve)

        if catalog_entry:
            canonical_fam = catalog_entry.get("family", fam_str)
            catalog_role = catalog_entry.get("crypto_role", role_str)
            is_qv = bool(catalog_entry.get("quantum_vulnerable", False))
            attack_type = catalog_entry.get("quantum_attack_type", "None known")
            is_deprecated = bool(catalog_entry.get("deprecated_or_disallowed", False))
            bits = catalog_entry.get("key_or_hash_size_bits", key_size)
        else:
            canonical_fam = fam_str
            catalog_role = role_str
            is_qv = (canonical_fam == "asymmetric")
            attack_type = "Shor" if is_qv else "Grover"
            is_deprecated = False
            bits = key_size

        # Post-Quantum Cryptography & Hybrids -> 0.0 susceptibility (no classical Shor vulnerability)
        if (
            canonical_fam in ("pqc", "hybrid")
            or any(p in algo_str.upper() for p in ["ML-KEM", "ML-DSA", "SLH-DSA", "KYBER", "DILITHIUM", "SPHINCS"])
            or "+" in algo_str
        ):
            return 0.0, False

        # Symmetric Cryptography
        if canonical_fam == "symmetric":
            if is_deprecated or any(w in algo_str.upper() for w in ["DES", "3DES", "RC4", "BLOWFISH"]):
                return 0.80, False
            if bits == 128 or "128" in algo_str:
                return 0.15, False
            if bits == 192 or "192" in algo_str:
                return 0.05, False
            # AES-256, ChaCha20 -> 0.0 (Quantum-safe against Grover with 128 bits post-quantum security)
            return 0.0, False

        # Asymmetric Cryptography (Shor's Algorithm)
        if (
            canonical_fam in ("asymmetric", "ecc", "dh", "dsa", "rsa", "public_key")
            or attack_type == "Shor"
            or is_qv
            or any(k in algo_str.upper() for k in ["ECC", "ECDSA", "ECDH", "ED25519", "ED448", "X25519", "X448", "RSA", "DH", "DSA", "ELGAMAL"])
        ):
            if catalog_role in ("key_establishment", "encryption", "kdf") or any(k in algo_str.upper() for k in ["RSA", "DH", "ECDH", "X25519", "X448", "ECC"]):
                return 1.0, True
            # Signatures and asymmetric keys
            return 0.70, True

        if canonical_fam in ("hash", "mac") or catalog_role in ("hash", "mac"):
            return 0.0, False

        return 0.0, is_qv

    @classmethod
    def calculate_impact_multiplier(
        cls,
        data_sensitivity: int = 3,
        business_criticality: int = 3,
    ) -> float:
        """
        Calculates normalized impact multiplier M_impact in [0.2, 1.0].
        M_impact = (data_sensitivity * 0.6 + business_criticality * 0.4) / 5.0
        """
        sens = max(1, min(5, int(data_sensitivity)))
        crit = max(1, min(5, int(business_criticality)))
        m_impact = (sens * 0.6 + crit * 0.4) / 5.0
        return round(m_impact, 4)

    @classmethod
    def solve_mosca_inequality(
        cls,
        X_migration_time: float,
        Y_data_lifetime: float,
        Z_time_to_crqc: float,
        assessment_year: int = 2026,
        quantum_horizon_year: int = 2033,
        s_crypto: float = 1.0,
        m_impact: float = 1.0,
    ) -> Dict[str, Any]:
        """
        Solves Mosca's theorem inequality X + Y > Z and derives all timeline metrics.
        """
        X = max(0.0, float(X_migration_time))
        Y = max(0.0, float(Y_data_lifetime))
        Z = max(0.0, float(Z_time_to_crqc))

        X_plus_Y = round(X + Y, 2)
        delta_M = round(X_plus_Y - Z, 2)  # Deficit if > 0, buffer if <= 0

        migration_completion_year = round(assessment_year + X, 1)
        data_expiry_year = round(assessment_year + Y, 1)
        must_start_by_year = round(assessment_year + Z - X, 1)
        is_overdue = bool(must_start_by_year <= assessment_year)

        # Mosca Inequality is ONLY applicable if the primitive is actually vulnerable (s_crypto > 0.10)
        is_applicable = bool(s_crypto >= 0.15)
        inequality_satisfied = bool(is_applicable and X_plus_Y > Z)

        # Calculate Normalized Mosca Risk Index
        if is_applicable and X_plus_Y > 0.0:
            deficit_ratio = min(1.0, max(0.0, delta_M) / X_plus_Y)
        else:
            deficit_ratio = 0.0

        mosca_risk_index = round(s_crypto * deficit_ratio * m_impact, 4)

        # Determine Migration Posture & Urgency Tier
        if not is_applicable or s_crypto == 0.0:
            posture: Literal["MIGRATION_DEFICIT", "MIGRATION_OVERDUE", "SAFE_BUFFER", "QUANTUM_RESILIENT"] = "QUANTUM_RESILIENT"
            urgency_tier: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"] = "NEGLIGIBLE"
            effective_deficit = 0.0
            effective_start_deadline = None
        elif is_overdue and s_crypto >= 0.70:
            posture = "MIGRATION_OVERDUE"
            urgency_tier = "CRITICAL"
            effective_deficit = delta_M
            effective_start_deadline = must_start_by_year
        elif inequality_satisfied:
            posture = "MIGRATION_DEFICIT"
            if delta_M >= 5.0 and s_crypto >= 0.70:
                urgency_tier = "CRITICAL"
            elif delta_M >= 2.0 and s_crypto >= 0.50:
                urgency_tier = "HIGH"
            else:
                urgency_tier = "MEDIUM"
            effective_deficit = delta_M
            effective_start_deadline = must_start_by_year
        else:
            posture = "SAFE_BUFFER"
            urgency_tier = "LOW" if (s_crypto >= 0.70 and delta_M > -2.0) else "NEGLIGIBLE"
            effective_deficit = delta_M
            effective_start_deadline = must_start_by_year

        return {
            "variables": {
                "X_migration_time_years": X,
                "Y_data_lifetime_years": Y,
                "Z_time_to_crqc_years": Z,
                "X_plus_Y": X_plus_Y,
            },
            "timeline": {
                "assessment_year": assessment_year,
                "projected_crqc_year": quantum_horizon_year,
                "migration_completion_year": migration_completion_year,
                "data_expiry_year": data_expiry_year,
                "mosca_deficit_years": effective_deficit,
                "must_start_by_year": effective_start_deadline,
                "is_overdue_to_start": is_overdue if is_applicable else False,
                "is_applicable": is_applicable,
            },
            "inequality_satisfied": inequality_satisfied,
            "urgency_tier": urgency_tier,
            "mosca_risk_index": mosca_risk_index,
            "migration_posture": posture,
        }

    @classmethod
    def determine_migration_guidance(
        cls,
        posture: str,
        urgency_tier: str,
        algorithm_name: str,
        X_migration_time: float,
        completion_year: float,
        crqc_year: int,
        must_start_year: float,
    ) -> str:
        """
        Generates deterministic migration action guidance.
        """
        algo_upper = algorithm_name.upper()
        if posture == "MIGRATION_OVERDUE":
            return (
                f"P0 - OVERDUE: Migration time ({X_migration_time} yrs) exceeds time to CRQC. "
                f"Migration should have commenced by {must_start_year:.0f}. Initiate emergency transition to PQC immediately."
            )
        elif urgency_tier == "CRITICAL":
            return (
                f"P0 - CRITICAL DEFICIT: Begin PQC migration immediately. Target completion by {completion_year:.0f} "
                f"well before projected {crqc_year} quantum horizon."
            )
        elif urgency_tier == "HIGH":
            return (
                f"P1 - HIGH PRIORITY: Allocate engineering resources to migrate {algorithm_name} before {must_start_year:.0f} deadline."
            )
        elif urgency_tier == "MEDIUM":
            return (
                f"P2 - MODERATE: Plan cryptographic migration in upcoming roadmap; start transition before {must_start_year:.0f}."
            )
        elif posture == "QUANTUM_RESILIENT":
            return (
                f"P4 - SAFE: {algorithm_name} is post-quantum secure. No migration required under current standards."
            )
        return (
            f"P3 - SAFE BUFFER: Current migration buffer is sufficient under {crqc_year} scenario. Review timeline periodically."
        )
