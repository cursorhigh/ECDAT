"""Seed demo data: run the demo scan pipeline once for a populated dashboard.

Usage:
    python manage.py seed_demo
"""

from django.core.management.base import BaseCommand

from segments.scraping.discovery.services import run_demo_scan
from core.models import log_action


class Command(BaseCommand):
    help = "Seed ECDAT with demo-mode discovery data."

    def handle(self, *args, **options):
        job = run_demo_scan()
        self.stdout.write(
            self.style.SUCCESS(
                f"Demo scan complete: ScanJob #{job.pk} with {job.findings_count} raw findings."
            )
        )
        log_action("demo_seeded", "Demo dataset seeded via management command")
        self.stdout.write(
            self.style.SUCCESS("Done. Start the server and open the dashboard.")
        )
