"""SqliteHuey task-queue configuration.

Huey's django integration reads the `HUEY` dict from Django settings. Setting
`huey_class` to `huey.SqliteHuey` and `connection.filename` to our own Sqlite
file keeps the queue entirely separate from the app database (db.sqlite3).
App DB rows remain the authoritative source of truth.

Important: do not import `huey.contrib.djhuey` here -- that module reads
`settings.HUEY` at import time, creating a circular dependency. Only build the
plain dict below.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[3]

# Sqlite queue file kept separate from the app database.
HUEY_DB = os.getenv("HUEY_DB", str(BASE_DIR / "huey.sqlite3"))

HUEY = {
    "name": "ecdat-crypto-scan",
    "huey_class": "huey.SqliteHuey",
    "connection": {"filename": HUEY_DB},
    # Real asynchronous queueing by default; set HUEY_IMMEDIATE=1 to run tasks
    # inline/synchronously (handy for tests).
    "immediate": os.getenv("HUEY_IMMEDIATE", "0") == "1",
    "consumer": {
        "workers": max(1, (os.cpu_count() or 1) // 2),
        "worker_type": "thread",
        "loglevel": "INFO",
    },
}
