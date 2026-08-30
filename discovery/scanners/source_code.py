"""Source-code scanner.

Delegates to the crypto-artefact scanner (the dedicated hand-off skeleton for
the security engineer). Kept as a thin alias so existing references keep
working; the real implementation lives in ``crypto_artefact.py``.
"""

from .crypto_artefact import CryptoArtefactScanner


class SourceCodeScanner(CryptoArtefactScanner):
    """Backwards-compatible alias for :class:`CryptoArtefactScanner`."""
