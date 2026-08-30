"""Filesystem walking and chunking for the crypto-scan pipeline.

`split_paths_into_chunks` is the single deterministic splitter used both by
the request handler (start_scan) and the crash-recovery re-enqueue, so a
chunk always maps to the same file list regardless of who computes it.
"""

import os

EXCLUDED_DIRS = {".git", ".hg", ".svn", "node_modules", "venv", "__pycache__", ".venv"}
MAX_FILES_PER_SCAN = 200_000


def walk_scan_files(root: str):
    """Yield regular file paths under `root`, skipping VCS/dependency dirs."""
    root = os.path.abspath(os.path.expanduser(root))
    if not os.path.isdir(root):
        raise NotADirectoryError(f"Not a directory: {root}")

    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames
            if not d.startswith(".") and d not in EXCLUDED_DIRS
        )
        for name in sorted(filenames):
            yield os.path.join(dirpath, name)
            count += 1
            if count >= MAX_FILES_PER_SCAN:
                return


def split_paths_into_chunks(paths: list[str], n: int) -> list[list[str]]:
    """Split a flat list of file paths into `n` roughly equal chunks.

    Chunking is deterministic: paths are split in order, so chunk `i` always
    owns the same path slice regardless of caller. Returns `n` lists (trailing
    chunks may be empty when there are fewer paths than chunks).
    """
    n = max(1, n)
    if not paths:
        return [[] for _ in range(n)]
    size = max(1, -(-len(paths) // n))  # ceil division
    return [paths[i * size:(i + 1) * size] for i in range(n)]
