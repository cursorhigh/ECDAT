"""ECDAT data-boundary helpers.

Demo mode is gone. Previously a 'mode' separated synthetic (demo) data from real
(actual) data at the database level, with each mode mapped to its own alias and
`ECDAT_ACTIVE_MODE` choosing between them. There is one database now, so these
helpers exist only to keep the ~200 existing `using=db` call sites working
without a risky, wide-reaching rewrite of every query.

They deliberately keep their old signatures. `db_alias_for_mode(mode)` still
accepts an argument and ignores it, so callers that thread a mode through
`log_action(...` or a `Mode.ACTUAL` value keep working while that
plumbing is removed separately.
"""

ACTUAL_DB = "default"

# The single data boundary. Kept as a one-tuple so command-line sweeps that
# iterate MODES still run -- they just make a single pass now.
MODES = ("actual",)


def db_alias_for_mode(mode: str = ACTUAL_DB) -> str:
    """Return the database alias. There is only one, whatever `mode` says."""
    return ACTUAL_DB


def active_mode() -> str:
    return "actual"


def active_db() -> str:
    """Return the database alias in use. Always `default`."""
    return ACTUAL_DB
