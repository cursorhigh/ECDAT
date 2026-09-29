"""Worker/queue liveness for the health probe.

Why this exists
---------------
``/api/health/`` used to report only the service name, mode and database. It
said nothing about the queue, so the settings page had nothing to read and
rendered a hardcoded "Worker status: Unavailable" -- which is indistinguishable
from a real outage. Three facts are now actually measured:

* whether the consumer process is alive (heartbeat, not inference)
* how much work is waiting (queue depth, straight from the SqliteHuey file)
* whether the queue is even in play (HUEY_IMMEDIATE runs tasks inline)

Why a heartbeat is necessary
----------------------------
Queue depth cannot answer "is the worker up?" -- an idle queue and a dead
worker look identical (0 pending in both cases). So the consumer writes a
timestamp into huey's own ``kv`` table every few seconds, and liveness is
decided by how fresh that stamp is.

Storage is huey's ``kv`` table in the queue file rather than a new model: the
queue DB is a separate, disposable artefact, the write is a single row upsert,
and nothing has to be migrated.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time

logger = logging.getLogger(__name__)

# Key in huey's kv table. Namespaced so it cannot collide with a task's own keys.
HEARTBEAT_KEY = "ecdat:worker:heartbeat"

# How often the consumer thread refreshes the stamp.
HEARTBEAT_INTERVAL_SECONDS = 15

# A stamp older than this means the consumer is gone. Three missed beats plus
# slack, so a single slow write does not flap the status to "offline".
HEARTBEAT_STALE_SECONDS = 60

_QUEUE_LOCK = threading.Lock()


def queue_file() -> str | None:
    """Absolute path of the SqliteHuey file, or None when the queue is inline.

    Read from settings rather than imported from ``hueyconf`` so that the
    health probe does not have to import the huey settings module.
    """
    from django.conf import settings

    config = getattr(settings, "HUEY", None) or {}
    if config.get("immediate"):
        return None
    connection = config.get("connection") or {}
    filename = connection.get("filename") or os.getenv("HUEY_DB")
    return str(filename) if filename else None


def _connect(path: str) -> sqlite3.Connection:
    # Short timeout and WAL so a probe never blocks behind a worker's write.
    connection = sqlite3.connect(path, timeout=2.0)
    connection.execute("PRAGMA busy_timeout = 2000")
    return connection


def write_heartbeat(detail: str = "", workers: int | None = None) -> bool:
    """Record that a live consumer just ticked. Returns True on success."""
    path = queue_file()
    if not path:
        return False
    payload = json.dumps(
        {
            "at": time.time(),
            "pid": os.getpid(),
            "detail": detail,
            "workers": workers,
        }
    )
    try:
        with _QUEUE_LOCK, _connect(path) as connection:
            connection.execute(
                "INSERT INTO kv (queue, key, value) VALUES ('', ?, ?) "
                "ON CONFLICT(queue, key) DO UPDATE SET value = excluded.value",
                (HEARTBEAT_KEY, payload),
            )
        return True
    except Exception:  # noqa: BLE001 - a missed heartbeat must not kill the worker
        logger.debug("Could not write the worker heartbeat", exc_info=True)
        return False


def read_heartbeat(path: str) -> dict | None:
    try:
        with _QUEUE_LOCK, _connect(path) as connection:
            row = connection.execute(
                "SELECT value FROM kv WHERE queue = '' AND key = ?", (HEARTBEAT_KEY,)
            ).fetchone()
    except Exception:  # noqa: BLE001 - the probe must never 500
        return None
    if not row:
        return None
    try:
        return json.loads(row[0])
    except (TypeError, ValueError):
        return None


def _queue_depth(path: str) -> tuple[int, int]:
    """(pending, scheduled) from the queue file. Missing tables read as zero."""
    pending = scheduled = 0
    try:
        with _QUEUE_LOCK, _connect(path) as connection:
            pending = connection.execute("SELECT COUNT(*) FROM task").fetchone()[0]
            try:
                scheduled = connection.execute("SELECT COUNT(*) FROM schedule").fetchone()[0]
            except sqlite3.Error:
                scheduled = 0
    except Exception:  # noqa: BLE001
        logger.debug("Could not read queue depth", exc_info=True)
    return pending, scheduled


def worker_status() -> dict:
    """Worker and queue state, shaped for the health payload.

    Keys are always present so the frontend never has to guard on undefined:

    ``mode``      "inline" when tasks run in the web process, else "queue"
    ``running``   True only when a heartbeat is fresh
    ``state``     "online" | "idle" | "stale" | "not_running" | "inline" | "unknown"
    ``pending``   tasks waiting
    ``scheduled`` tasks waiting for their run time
    """
    from django.conf import settings

    config = getattr(settings, "HUEY", None) or {}
    consumer = config.get("consumer") or {}
    configured_workers = consumer.get("workers")

    path = queue_file()
    if path is None:
        return {
            "mode": "inline",
            "running": True,
            "state": "inline",
            "pending": 0,
            "scheduled": 0,
            "workers": 0,
            "last_seen": None,
            "age_seconds": None,
            "detail": "HUEY_IMMEDIATE is set, so work runs inside the web process. No separate worker is needed.",
        }

    if not os.path.exists(path):
        return {
            "mode": "queue",
            "running": False,
            "state": "unknown",
            "pending": 0,
            "scheduled": 0,
            "workers": configured_workers,
            "last_seen": None,
            "age_seconds": None,
            "detail": f"No queue file at {path}. Start the worker with `manage.py run_huey`.",
        }

    beat = read_heartbeat(path)
    pending, scheduled = _queue_depth(path)

    last_seen = None
    age = None
    if beat and beat.get("at"):
        age = max(0.0, time.time() - float(beat["at"]))
        last_seen = beat.get("at")

    running = age is not None and age <= HEARTBEAT_STALE_SECONDS
    if running:
        state = "idle" if pending == 0 else "online"
    elif age is None:
        state = "not_running"
    else:
        state = "stale"

    if state == "not_running":
        detail = "No worker heartbeat has ever been written. Run `manage.py run_huey` in a second process."
    elif state == "stale":
        detail = f"Worker last checked in {int(age)}s ago, so it is probably not running."
    elif state == "idle":
        detail = f"Worker is running and the queue is empty. {configured_workers or 1} thread(s)."
    else:
        detail = f"Worker is running with {pending} task(s) queued."

    return {
        "mode": "queue",
        "running": running,
        "state": state,
        "pending": pending,
        "scheduled": scheduled,
        "workers": configured_workers,
        "last_seen": last_seen,
        "age_seconds": int(age) if age is not None else None,
        "detail": detail,
    }


class HeartbeatThread(threading.Thread):
    """Daemon thread that keeps the worker liveness stamp fresh.

    Started by the ``run_huey`` command. It stops on its own once the consumer
    returns, and it never raises into the consumer.
    """

    def __init__(self, workers: int | None = None, interval: int = HEARTBEAT_INTERVAL_SECONDS):
        super().__init__(name="ecdat-worker-heartbeat", daemon=True)
        self._workers = workers
        self._interval = interval
        self._stop = threading.Event()

    def run(self) -> None:  # pragma: no cover - timing loop
        write_heartbeat(detail="worker starting", workers=self._workers)
        while not self._stop.wait(self._interval):
            if not write_heartbeat(detail="worker alive", workers=self._workers):
                logger.debug("Heartbeat write failed; will retry on the next tick")

    def stop(self) -> None:
        self._stop.set()
