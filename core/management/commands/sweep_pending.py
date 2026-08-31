"""Re-queue work a previous ECDAT process left pending/unfinished.

Startup recovery used by run_all.sh (and by run_huey at boot): any scan,
analysis run, mitigation plan or crypto-scan chunk left queued/running after
a crash or a hard stop is reset and re-dispatched so it completes.

    python manage.py sweep_pending

New work is enqueued on the huey queue (persistent between processes) so a
running worker picks it up; every task is guarded by a compare-and-swap so
concurrent or repeated sweeps never double-execute a row.
"""

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Re-queue pending/unfinished scans, analyses, plans and chunks."

    def handle(self, *args, **options):
        from analysis.runner import sweep_pending_runs
        from crypto_scan.pipeline import sweep_stale_chunks
        from discovery.services import sweep_pending_scans
        from mitigation.planner import sweep_pending_plans

        def _safe(label, fn):
            """Best-effort sweep: a DB hiccup (e.g. a mode DB not yet migrated)
            must never abort startup recovery of the other items."""
            try:
                return fn()
            except Exception as exc:  # noqa: BLE001
                self.stdout.write(self.style.ERROR(f"{label} sweep skipped: {exc}"))
                return 0

        scans = _safe("scan", sweep_pending_scans)
        runs = _safe("analysis", sweep_pending_runs)
        plans = _safe("mitigation", sweep_pending_plans)
        chunks = _safe("crypto chunk", sweep_stale_chunks)

        total = scans + runs + plans + chunks
        if total:
            self.stdout.write(
                self.style.WARNING(
                    f"Recovered {total} pending item(s): "
                    f"{scans} scan(s), {runs} analysis run(s), "
                    f"{plans} mitigation plan(s), {chunks} crypto chunk(s)."
                )
            )
        else:
            self.stdout.write("No pending items to recover.")