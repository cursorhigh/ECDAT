"""ECDAT mode helpers.

A 'mode' separates demo (synthetic) data from actual (real) data at the
database level. Each mode maps to its own database alias; the active mode
is a config flag (ECDAT_ACTIVE_MODE) so the two are a hard boundary.
"""

MODES = ("demo", "actual")

DEMO_DB = "demo"
ACTUAL_DB = "default"


def db_alias_for_mode(mode: str) -> str:
    """Return the database alias a mode lives in."""
    return DEMO_DB if mode == "demo" else ACTUAL_DB


def active_mode():
    from django.conf import settings

    return settings.ECDAT.get("ACTIVE_MODE", "demo")


def active_db():
    """Return the database alias for the currently active mode."""
    return db_alias_for_mode(active_mode())
