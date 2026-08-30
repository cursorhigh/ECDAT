"""Thin wrapper around YARA for crypto rule matching.

Rules are compiled once per process (guarded) from crypto_rules.yar so huey
workers don't recompile on every task.
"""

import os

import yara

from config import settings as django_settings

_rules = None


def _rules_path() -> str:
    return getattr(django_settings, "CRYPTO_YARA_RULES", None) or os.path.join(
        django_settings.BASE_DIR, "crypto_rules.yar"
    )


def get_rules():
    """Return the compiled YARA rules, compiling once per process."""
    global _rules
    if _rules is None:
        path = _rules_path()
        if not os.path.exists(path):
            raise FileNotFoundError(f"YARA rules file not found: {path}")
        _rules = yara.compile(filepath=path)
    return _rules


def match_file(file_path: str) -> list[dict]:
    """Run the crypto YARA rules against a single file.

    Returns a list of match dicts like:
        [{"rule": "Crypto_RSA", "algorithm": "RSA", "kind": "public_key",
          "strings": ["RSA", ...], "count": n}, ...]
    Empty list when no rules match (or the file is unreadable/binary-large).
    """
    rules = get_rules()
    matches = []
    try:
        data = rules.match(file_path, timeout=10)
    except Exception:
        # Unreadable file, timeout, or matching error -> treat as no match.
        return []

    for m in data:
        entry = {
            "rule": m.rule,
            "algorithm": m.meta.get("algorithm", ""),
            "kind": m.meta.get("kind", ""),
            "count": len(m.strings or []),
        }
        string_data = []
        for s in (m.strings or [])[:8]:
            try:
                raw = s[2] if len(s) > 2 else b""
                string_data.append(raw[:64].decode("utf-8", errors="replace"))
            except Exception:
                continue
        entry["strings"] = string_data
        matches.append(entry)
    return matches
