"""
MOSCA+ Module Custom Exceptions

Defines custom exception classes for MOSCA+ cryptographic assessment agent.
"""


class MOSCAError(Exception):
    """Base exception for all MOSCA+ errors."""
    pass


class MOSCAInputValidationError(MOSCAError):
    """Raised when input CBOM asset structure is invalid."""
    pass


class MOSCAOutputValidationError(MOSCAError):
    """Raised when output MOSCA assessment JSON schema or field validation fails."""
    pass


class MOSCALLMError(MOSCAError):
    """Raised when LLM API execution or JSON extraction fails fatally."""
    pass
