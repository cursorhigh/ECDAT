"""Run the huey consumer for the crypto-scan queue.

Usage:
    python manage.py run_huey [options]

Supported options (matching run_all.sh and the huey consumer):
    --loglevel INFO|DEBUG|WARNING|ERROR    root logger level (default INFO)
    --workers N                            worker threads (default: settings)
    --worker-type thread|process|greenlet  execution model
    --logfile FILE                         write logs to FILE
    --verbose / --quiet                    log verbosity shortcuts

On startup it sweeps ScanChunks stuck in 'running' for more than 5 minutes,
resets them to 'pending' and re-enqueues a huey task for each, plus re-queues
stuck scans, analyses and mitigation plans left by a previous process, then
launches the consumer.
"""

import logging

from django.conf import settings
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Run the huey task consumer for crypto scans (with crash recovery)."

    def add_arguments(self, parser):
        parser.add_argument("--loglevel", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                            default=None, help="Root logger level (default INFO).")
        parser.add_argument("--workers", type=int, default=None,
                            help="Number of worker threads (default: settings.HUEY).")
        parser.add_argument("--worker-type", choices=["thread", "process", "greenlet"],
                            default=None, help="Worker execution model (default: thread).")
        parser.add_argument("--logfile", default=None, help="Write logs to this file.")
        parser.add_argument("--verbose", action="store_true", help="Verbose logging (DEBUG).")
        parser.add_argument("--quiet", action="store_true", help="Minimal logging (WARNING).")
        parser.add_argument("--simple", action="store_true", help="Simple log format.")

    def _setup_logging(self, loglevel, verbose, quiet, logfile, simple):
        if quiet:
            level = logging.WARNING
        elif verbose:
            level = logging.DEBUG
        else:
            level = getattr(logging, (loglevel or "INFO").upper(), logging.INFO)
        logger = logging.getLogger()
        logger.setLevel(level)
        if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
            handler = logging.FileHandler(logfile) if logfile else logging.StreamHandler()
            node = "%(threadName)s"
            fmt = "[%(asctime)s] %(levelname)s:%(name)s:" + node + ":%(message)s" if not simple \
                else "%(asctime)s %(message)s"
            handler.setFormatter(logging.Formatter(fmt))
            logger.addHandler(handler)

    def _consumer_kwargs(self, workers, worker_type):
        cfg = settings.HUEY.get("consumer") or {}
        kwargs = {}
        kwargs["workers"] = workers if workers else cfg.get("workers", 1)
        wtype = worker_type or cfg.get("worker_type", "thread")
        if wtype != "thread":
            kwargs["worker_type"] = wtype
        return kwargs

    def handle(self, *args, **options):
        from huey.contrib.djhuey import HUEY

        loglevel = options.pop("loglevel", None)
        workers = options.pop("workers", None)
        worker_type = options.pop("worker_type", None)
        logfile = options.pop("logfile", None)
        verbose = options.pop("verbose", False)
        quiet = options.pop("quiet", False)
        simple = options.pop("simple", False)
        self._setup_logging(loglevel, verbose, quiet, logfile, simple)

        # Crash-recovery sweep before the consumer starts draining the queue:
        # reset+re-queue stuck crypto chunks, scans, analyses and plans left
        # by a previous process (see also `manage.py sweep_pending`).
        from analysis.runner import sweep_pending_runs
        from crypto_scan.pipeline import sweep_stale_chunks
        from discovery.services import sweep_pending_scans
        from mitigation.planner import sweep_pending_plans

        def _safe(label, fn):
            """Best-effort recovery: a missing/unmigrated mode DB must never
            prevent the worker consumer from starting."""
            try:
                return fn()
            except Exception as exc:  # noqa: BLE001
                self.stdout.write(self.style.ERROR(f"Crash recovery: {label} sweep skipped: {exc}"))
                return 0

        chunks = _safe("crypto chunk", sweep_stale_chunks)
        scans = _safe("scan", sweep_pending_scans)
        runs = _safe("analysis", sweep_pending_runs)
        plans = _safe("mitigation", sweep_pending_plans)
        total = chunks + scans + runs + plans
        if total:
            self.stdout.write(
                self.style.WARNING(
                    f"Crash recovery: re-enqueued {total} pending item(s) "
                    f"({scans} scans, {runs} analysis, {plans} plans, {chunks} chunks)."
                )
            )
        else:
            self.stdout.write("Crash recovery: no pending items to reset.")

        consumer = HUEY.create_consumer(**self._consumer_kwargs(workers, worker_type))
        consumer.run()