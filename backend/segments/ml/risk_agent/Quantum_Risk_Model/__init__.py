"""
ECDAT Quantum Risk Model Package
Provides direct access to inference API for Django and enterprise services.
"""

try:
    from .src.predict import (
        predict_quantum_risk,
        validate_input_record,
        canonicalize_and_validate_record,
        get_model_artifacts,
    )
except (ImportError, ValueError):
    from src.predict import (
        predict_quantum_risk,
        validate_input_record,
        canonicalize_and_validate_record,
        get_model_artifacts,
    )

__all__ = [
    "predict_quantum_risk",
    "validate_input_record",
    "canonicalize_and_validate_record",
    "get_model_artifacts",
]
__version__ = "1.1.0"
