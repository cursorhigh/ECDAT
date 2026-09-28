"""
ECDAT ML Post-Quantum Risk Analysis Module
"""


def __getattr__(name):
    if name in ("ECDATPipeline", "run_ecdat_pipeline"):
        from .pipeline import ECDATPipeline, run_ecdat_pipeline

        if name == "ECDATPipeline":
            return ECDATPipeline
        return run_ecdat_pipeline
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["ECDATPipeline", "run_ecdat_pipeline"]

