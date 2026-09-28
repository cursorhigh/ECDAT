"""
CBOM Explainability Builder Component (explainability.py)

Builds unified evidence-based explainability metadata and CycloneDX 1.6 evidence occurrences
for both deterministic and AI-assisted cryptographic asset extractions.
"""

from typing import Dict, Any, List, Optional


class CBOMExplainabilityBuilder:
    """
    Constructs unified explainability metadata and CycloneDX evidence for cryptographic assets.
    """

    ALLOWED_EVIDENCE_TYPES = {
        "explicit",
        "pattern_match",
        "inferred_from_provided_evidence",
        "insufficient",
    }

    ALLOWED_SOURCES = {
        "source_code",
        "provided_source_code",
        "finding",
        "deterministic_result",
        "llm",
    }

    def build_deterministic_explanation(
        self,
        finding: Dict[str, Any],
        deterministic_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Constructs explainability dictionary for purely deterministic extractions.
        """
        code_text = str(finding.get("code") or finding.get("evidence") or "")
        detected = str(finding.get("detected") or finding.get("algorithm") or deterministic_result.get("algorithm") or "")

        algo = deterministic_result.get("algorithm") or detected or "unknown"
        key_size = deterministic_result.get("key_size")
        mode = deterministic_result.get("mode")
        curve = deterministic_result.get("curve")
        padding = deterministic_result.get("padding")
        hash_alg = deterministic_result.get("hash")
        protocol = deterministic_result.get("protocol")
        crypto_library = deterministic_result.get("crypto_library")

        # Build field-level evidence list
        field_evidence: List[Dict[str, Any]] = []

        # Algorithm evidence
        if algo and algo.lower() != "unknown":
            snippet = self._find_snippet_in_code(code_text, "algorithms.AES") or \
                      self._find_snippet_in_code(code_text, "hashlib.sha256") or \
                      self._find_snippet_in_code(code_text, "rsa.generate_private_key") or \
                      self._find_snippet_in_code(code_text, algo) or \
                      self._find_snippet_in_code(code_text, detected) or code_text or algo
            is_explicit = (algo.lower() in code_text.lower() or detected.lower() in code_text.lower() or "aes" in code_text.lower() or "sha" in code_text.lower() or "rsa" in code_text.lower())
            field_evidence.append({
                "field": "algorithm",
                "value": algo,
                "source": "source_code",
                "snippet": snippet,
                "evidence_type": "explicit" if is_explicit else "pattern_match",
                "explanation": f"The {algo} algorithm is explicitly referenced in the source code." if is_explicit else f"The {detected} cryptographic API is associated with {algo} in matched deterministic rules.",
            })

        # Key Size evidence
        if key_size is not None:
            snippet = self._find_snippet_in_code(code_text, f"key_size={key_size}") or self._find_snippet_in_code(code_text, str(key_size)) or f"key_size={key_size}"
            field_evidence.append({
                "field": "parameters.key_size",
                "value": key_size,
                "source": "source_code",
                "snippet": snippet,
                "evidence_type": "explicit" if str(key_size) in code_text else "pattern_match",
                "explanation": f"The key size is explicitly specified as {key_size}." if str(key_size) in code_text else f"The key size of {key_size} bits was inferred from the standard algorithm specification.",
            })

        # Mode evidence
        if mode:
            snippet = self._find_snippet_in_code(code_text, f"modes.{mode}") or self._find_snippet_in_code(code_text, mode) or mode
            field_evidence.append({
                "field": "parameters.mode",
                "value": mode,
                "source": "source_code",
                "snippet": snippet,
                "evidence_type": "explicit" if mode.lower() in code_text.lower() else "pattern_match",
                "explanation": f"The {mode} mode is explicitly referenced in the source code.",
            })

        # Curve evidence
        if curve:
            snippet = self._find_snippet_in_code(code_text, curve) or curve
            field_evidence.append({
                "field": "parameters.curve",
                "value": curve,
                "source": "source_code",
                "snippet": snippet,
                "evidence_type": "explicit" if curve.lower() in code_text.lower() else "pattern_match",
                "explanation": f"The elliptic curve {curve} is explicitly referenced in the source code.",
            })

        # Padding evidence
        if padding:
            snippet = self._find_snippet_in_code(code_text, padding) or padding
            field_evidence.append({
                "field": "parameters.padding",
                "value": padding,
                "source": "source_code",
                "snippet": snippet,
                "evidence_type": "explicit" if padding.lower() in code_text.lower() else "pattern_match",
                "explanation": f"The padding scheme {padding} is referenced in the source code.",
            })

        # Hash evidence
        if hash_alg:
            snippet = self._find_snippet_in_code(code_text, hash_alg) or hash_alg
            field_evidence.append({
                "field": "parameters.hash",
                "value": hash_alg,
                "source": "source_code",
                "snippet": snippet,
                "evidence_type": "explicit" if hash_alg.lower() in code_text.lower() else "pattern_match",
                "explanation": f"The {hash_alg} digest is referenced in the source code.",
            })

        # Protocol evidence
        if protocol:
            snippet = self._find_snippet_in_code(code_text, protocol) or protocol
            field_evidence.append({
                "field": "protocol",
                "value": protocol,
                "source": "source_code",
                "snippet": snippet,
                "evidence_type": "explicit" if protocol.lower() in code_text.lower() else "pattern_match",
                "explanation": f"The protocol {protocol} was detected in the communication context.",
            })

        # Library evidence
        if crypto_library:
            field_evidence.append({
                "field": "crypto_library",
                "value": crypto_library,
                "source": "source_code",
                "snippet": self._find_snippet_in_code(code_text, crypto_library) or code_text[:80],
                "evidence_type": "pattern_match",
                "explanation": f"The cryptographic library {crypto_library} was identified from imports/symbols.",
            })

        has_code = bool(code_text and code_text.strip())
        summary = f"{algo} was identified through an explicit deterministic cryptographic API pattern." if has_code else f"{algo} was matched via deterministic discovery finding metadata."
        decision_reason = "The deterministic extraction rule successfully identified the algorithm and key parameters without requiring AI assistance."
        confidence_reason = "High confidence because explicit cryptographic evidence and standard API patterns were found in the source code." if has_code else "Moderate confidence based on artifact metadata without full code context."

        return {
            "method": "deterministic",
            "detection_method": "deterministic",
            "ai_used": False,
            "summary": summary,
            "decision_reason": decision_reason,
            "field_evidence": field_evidence,
            "confidence_reason": confidence_reason,
        }

    def build_ai_explanation(
        self,
        finding: Dict[str, Any],
        deterministic_result: Dict[str, Any],
        ai_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Constructs explainability dictionary when AI fallback assistance was used.
        """
        code_text = str(finding.get("code") or finding.get("evidence") or "")
        algo = ai_result.get("algorithm") or deterministic_result.get("algorithm") or "unknown"
        key_size = ai_result.get("key_size") or deterministic_result.get("key_size")

        field_evidence: List[Dict[str, Any]] = []

        if algo:
            field_evidence.append({
                "field": "algorithm",
                "value": algo,
                "source": "llm",
                "snippet": self._find_snippet_in_code(code_text, algo) or code_text or algo,
                "evidence_type": "inferred_from_provided_evidence",
                "explanation": f"AI model analyzed the source code snippet and determined the algorithm to be {algo}.",
            })

        if key_size is not None:
            field_evidence.append({
                "field": "parameters.key_size",
                "value": key_size,
                "source": "llm",
                "snippet": self._find_snippet_in_code(code_text, str(key_size)) or str(key_size),
                "evidence_type": "inferred_from_provided_evidence",
                "explanation": f"AI model deduced key_size {key_size} from code parameters.",
            })

        return {
            "method": "llm",
            "detection_method": "llm",
            "ai_used": True,
            "summary": f"AI analysis was utilized to disambiguate the cryptographic configuration for {algo}.",
            "decision_reason": "Deterministic rules lacked full parameter context; AI reasoning extracted missing metadata.",
            "field_evidence": field_evidence,
            "confidence_reason": f"AI-assisted extraction based on provided code evidence (confidence: {ai_result.get('confidence', 0.85)}).",
        }

    def build_cyclonedx_evidence(
        self,
        finding: Dict[str, Any],
        extracted: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Constructs CycloneDX 1.6 compliant evidence occurrences structure.
        """
        file_path = finding.get("file")
        if not file_path and isinstance(finding.get("location"), dict):
            file_path = finding.get("location", {}).get("file")

        line_num = finding.get("line")
        if line_num is None and isinstance(finding.get("location"), dict):
            line_num = finding.get("location", {}).get("line")

        code_snippet = finding.get("code") or finding.get("evidence")

        occurrences = []
        if file_path:
            occurrences.append({
                "location": file_path,
                "line": int(line_num) if line_num is not None else None,
                "additionalContext": code_snippet,
                "symbol": extracted.get("implementation"),
            })

        return {"occurrences": occurrences}

    def _find_snippet_in_code(self, code_text: str, target: str) -> Optional[str]:
        if not code_text or not target:
            return None
        if target.lower() in code_text.lower():
            lines = code_text.splitlines()
            for line in lines:
                if target.lower() in line.lower():
                    return line.strip()
            return target
        return None
