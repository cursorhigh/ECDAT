"""Enforce the workstream-segment boundary contract (import-linter).

Runs the layer contract defined in `.importlinter` via the Python API so it
keeps working regardless of how the virtualenv was relocated (Windows console
script shims embed an absolute interpreter path).

Usage:
    python scripts/lint_imports.py
"""

from importlinter.cli import lint_imports_command


if __name__ == "__main__":
    raise SystemExit(lint_imports_command())