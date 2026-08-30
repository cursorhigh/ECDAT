"""Run the huey consumer for the crypto-scan queue.

Usage:
    python manage.py run_huey [huey-consumer-options...]

On startup it sweeps ScanChunks stuck in 'running' for more than 5 minutes,
resets them to 'pending' and re-enqueues a huey task for each, then launches
the consumer. Huey signal handlers (consumer boot) are wired here so the
sweep runs automatically.

Extra arguments are passed through to huey's consumer (`--workers 4`,
`--loglevel DEBUG`, etc.):
    python manage.py run_huey --workers 4
"""

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Run the huey task consumer for crypto scans (with crash recovery)."

    def add_arguments(self, parser):
        parser.add_argument(
            "args",
            nargs="*",
            help="Huey consumer options, passed through as-is (e.g. --workers 4).",
        )

    def handle(self, *args, **options):
        from huey.contrib.djhuey import HUEY

        # Crash recovery sweep before the consumer starts draining the queue.
        from crypto_scan.pipeline import sweep_stale_chunks

        sweeps = sweep_stale_chunks()
        if sweeps:
            self.stdout.write(
                self.style.WARNING(
                    f"Crashed-chunk recovery: re-enqueued {sweeps} stale chunk(s)."
                )
            )
        else:
            self.stdout.write("Crash recovery: no stale chunks to reset.")

        # Pass through huey consumer arguments.
        consumer = HUEY.create_consumer(worker_type="thread", *args)
        consumer.run()
