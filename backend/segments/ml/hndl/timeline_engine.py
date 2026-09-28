"""
HNDL Deterministic Timeline & Threat Engine (timeline_engine.py)

Implements pure, reproducible mathematical and policy rules to evaluate:
1. Cryptographic Susceptibility (S_crypto) using NIST/FIPS crypto catalog lookups
2. Interception / Harvestability (S_harvest) factoring network egress, transit, and PFS status
3. Confidentiality Timeline vs. Scenario Quantum Threat Horizon (Compromise Window Delta T)
4. Business & Data Impact Multiplier (M_impact)
5. Composite Bounded HNDL Exposure Score (0.0 <= score <= 1.0)
"""

from typing import Dict, Any, Optional, Tuple, Literal, Union
from segments.ml.cbom.crypto_catalog import lookup_crypto_algorithm


class HNDLTimelineEngine:
    """
    Deterministic mathematical engine for evaluating Harvest Now, Decrypt Later threats.
    """

    DEFAULT_QUANTUM_HORIZON_YEAR = 2033
    DEFAULT_ASSESSMENT_YEAR = 2026

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
        Determines the cryptographic susceptibility score S_crypto in [0.0, 1.0]
        based on quantum cryptanalysis threat (Shor vs. Grover).

        :return: Tuple (S_crypto: float, quantum_vulnerable: bool)
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

        # Post-Quantum Cryptography (FIPS 203, 204, 205) -> Fully immune to HNDL
        if canonical_fam == "pqc" or any(p in algo_str.upper() for p in ["ML-KEM", "ML-DSA", "SLH-DSA", "KYBER", "DILITHIUM"]):
            return 0.0, False

        # Symmetric Cryptography (Grover's Algorithm effect)
        if canonical_fam == "symmetric":
            if is_deprecated or any(w in algo_str.upper() for w in ["DES", "3DES", "RC4", "BLOWFISH"]):
                return 0.80, True  # Broken / severely reduced security
            if bits == 128 or "128" in algo_str:
                return 0.35, False  # Grover reduces security to ~64-bit brute force
            if bits == 192 or "192" in algo_str:
                return 0.15, False
            # 256-bit symmetric (AES-256, ChaCha20-Poly1305) provides 128 bits of quantum security (NIST Cat 5 / quantum-resistant)
            return 0.05, False

        # Asymmetric Cryptography (Shor's Algorithm)
        if canonical_fam == "asymmetric" or attack_type == "Shor" or is_qv:
            # Key establishment & public-key encryption (RSA-OAEP, DH, ECDH, X25519) allow retrospective decryption of ciphertext
            if catalog_role in ("key_establishment", "encryption", "kdf") or any(k in algo_str.upper() for k in ["RSA", "DH", "ECDH", "X25519", "X448"]):
                return 1.0, True
            # Signatures (ECDSA, Ed25519, RSA-PSS, DSA) cannot decrypt ciphertext directly, but allow retrospective forgery of tokens/signatures
            return 0.30, True

        # Hash / MAC / KDF without asymmetric encapsulation -> No ciphertext to retrospectively decrypt
        if canonical_fam in ("hash", "mac") or catalog_role in ("hash", "mac"):
            return 0.0, False

        return 0.10, is_qv

    @classmethod
    def calculate_harvestability_score(
        cls,
        internet_exposed: bool = False,
        external_facing: bool = False,
        data_in_transit: bool = True,
        data_at_rest: bool = False,
        lack_of_pfs: Union[bool, str, None] = "UNKNOWN",
        protocol: Optional[str] = None,
        storage_untrusted: bool = False,
    ) -> Tuple[float, Literal["HIGH", "MEDIUM", "LOW"], Literal["PFS_PRESENT", "LACK_OF_PFS", "UNKNOWN"]]:
        """
        Calculates interception / harvestability score S_harvest in [0.0, 1.0].
        Factors network perimeter exposure, transport vs storage, and Perfect Forward Secrecy.

        :return: Tuple (S_harvest: float, tier: Literal["HIGH", "MEDIUM", "LOW"], pfs_status)
        """
        proto_upper = str(protocol or "").upper()

        # 1. Resolve PFS status deterministically
        if isinstance(lack_of_pfs, bool):
            pfs_status: Literal["PFS_PRESENT", "LACK_OF_PFS", "UNKNOWN"] = "LACK_OF_PFS" if lack_of_pfs else "PFS_PRESENT"
        elif str(lack_of_pfs).upper() == "TRUE":
            pfs_status = "LACK_OF_PFS"
        elif str(lack_of_pfs).upper() == "FALSE":
            pfs_status = "PFS_PRESENT"
        else:
            # Deterministic inference from protocol context
            if "TLS 1.3" in proto_upper or "TLS1.3" in proto_upper or "QUIC" in proto_upper:
                pfs_status = "PFS_PRESENT"
            elif "SSH" in proto_upper:
                pfs_status = "PFS_PRESENT"
            elif "IPSEC" in proto_upper or "IKEV2" in proto_upper:
                pfs_status = "PFS_PRESENT"
            else:
                pfs_status = "UNKNOWN"

        # 2. Weighted component scoring
        w_internet = 0.35 if internet_exposed else 0.0
        w_external = 0.25 if external_facing else 0.0
        w_transit = 0.25 if data_in_transit else (0.10 if not data_at_rest else 0.0)
        
        if pfs_status == "LACK_OF_PFS":
            w_pfs = 0.15
        elif pfs_status == "UNKNOWN":
            w_pfs = 0.05
        else:
            w_pfs = 0.0

        w_storage = 0.15 if storage_untrusted else 0.0

        raw_score = w_internet + w_external + w_transit + w_pfs + w_storage

        # Baseline exposure: if in transit within internal network, minimum interceptability baseline is 0.15
        if raw_score == 0.0 and data_in_transit:
            raw_score = 0.15

        s_harvest = round(min(1.0, max(0.0, raw_score)), 4)

        if s_harvest >= 0.60:
            harvest_tier: Literal["HIGH", "MEDIUM", "LOW"] = "HIGH"
        elif s_harvest >= 0.30:
            harvest_tier = "MEDIUM"
        else:
            harvest_tier = "LOW"

        return s_harvest, harvest_tier, pfs_status

    @classmethod
    def calculate_timeline_metrics(
        cls,
        assessment_year: int = 2026,
        data_lifetime_years: float = 5.0,
        quantum_horizon_year: int = 2033,
    ) -> Dict[str, Any]:
        """
        Calculates data expiration vs. quantum threat horizon metrics.
        """
        lifetime = max(0.0, float(data_lifetime_years))
        data_expiry_year = assessment_year + lifetime
        exposure_window = max(0.0, data_expiry_year - quantum_horizon_year)
        compromised_while_sensitive = exposure_window > 0.0

        if lifetime > 0.0:
            timeline_factor = min(1.0, exposure_window / lifetime)
        else:
            timeline_factor = 0.0

        return {
            "assessment_year": assessment_year,
            "data_lifetime_years": lifetime,
            "data_expiry_year": round(data_expiry_year, 2),
            "projected_crqc_year": quantum_horizon_year,
            "exposure_window_years": round(exposure_window, 2),
            "compromised_while_sensitive": compromised_while_sensitive,
            "timeline_factor": round(timeline_factor, 4),
        }

    @classmethod
    def calculate_impact_multiplier(
        cls,
        data_sensitivity: int = 3,
        business_criticality: int = 3,
    ) -> float:
        """
        Calculates the normalized business impact multiplier M_impact in [0.2, 1.0].
        M_impact = (data_sensitivity * 0.6 + business_criticality * 0.4) / 5.0
        """
        sens = max(1, min(5, int(data_sensitivity)))
        crit = max(1, min(5, int(business_criticality)))
        m_impact = (sens * 0.6 + crit * 0.4) / 5.0
        return round(m_impact, 4)

    @classmethod
    def calculate_composite_hndl_score(
        cls,
        s_crypto: float,
        s_harvest: float,
        timeline_factor: float,
        m_impact: float,
    ) -> float:
        """
        Calculates the exact composite HNDL Exposure Score.
        Score = S_crypto * S_harvest * Timeline_Factor * M_impact
        """
        score = s_crypto * s_harvest * timeline_factor * m_impact
        return round(min(1.0, max(0.0, score)), 4)

    @classmethod
    def determine_applicability_and_urgency(
        cls,
        hndl_score: float,
        s_crypto: float,
        s_harvest: float,
        timeline_metrics: Dict[str, Any],
        data_sensitivity: int,
    ) -> Tuple[bool, Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"], Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"]]:
        """
        Determines HNDL applicability, urgency tier, and future decryption risk.
        """
        exposure_window = timeline_metrics.get("exposure_window_years", 0.0)
        lifetime = timeline_metrics.get("data_lifetime_years", 0.0)

        # HNDL is applicable if:
        # 1. Algorithm has non-zero crypto susceptibility to quantum attacks
        # 2. Data can be intercepted / harvested (S_harvest > 0)
        # 3. Protected data remains sensitive after quantum horizon (exposure_window > 0)
        applicable = bool(s_crypto > 0.0 and s_harvest > 0.0 and exposure_window > 0.0 and lifetime > 0.0)

        if not applicable:
            urgency: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"] = "NEGLIGIBLE"
            future_risk: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"] = "NEGLIGIBLE"
            return False, urgency, future_risk

        # Deterministic Urgency Tier Assignment
        if hndl_score >= 0.50 or (s_crypto == 1.0 and exposure_window >= 5.0 and data_sensitivity >= 4):
            urgency = "CRITICAL"
            future_risk = "CRITICAL"
        elif hndl_score >= 0.25 or (s_crypto >= 0.8 and exposure_window >= 2.0):
            urgency = "HIGH"
            future_risk = "HIGH"
        elif hndl_score >= 0.10 or (s_crypto >= 0.35 and exposure_window > 0.0):
            urgency = "MEDIUM"
            future_risk = "MEDIUM"
        else:
            urgency = "LOW"
            future_risk = "LOW"

        return True, urgency, future_risk

    @classmethod
    def determine_mitigation_priority(
        cls,
        urgency_tier: str,
        algorithm_name: str,
        crypto_role: str,
    ) -> str:
        """
        Generates deterministic remediation recommendations according to urgency and role.
        """
        algo_upper = algorithm_name.upper()
        if urgency_tier == "CRITICAL":
            if any(k in algo_upper for k in ["RSA", "ECDH", "DH", "X25519"]):
                return "P0 - Immediate transition to hybrid ML-KEM-768 or ephemeral quantum-safe key exchange to prevent retro-decryption."
            return "P0 - Immediate migration to NIST-approved post-quantum cryptography (FIPS 203 ML-KEM or FIPS 204 ML-DSA)."
        elif urgency_tier == "HIGH":
            return "P1 - Prioritize quantum-safe key encapsulation (ML-KEM-768) within upcoming cryptographic migration cycle."
        elif urgency_tier == "MEDIUM":
            return "P2 - Plan migration to post-quantum algorithm; ensure perfect forward secrecy (PFS) is enforced in the interim."
        elif urgency_tier == "LOW":
            return "P3 - Monitor quantum threat timeline; replace legacy ciphers with AES-256 or PQC standard during regular upgrade."
        return "P4 - No immediate HNDL mitigation required under current timeline scenario."
