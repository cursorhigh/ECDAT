"""Apply migrations to *both* databases.

The project keeps two fully independent databases (`default` for actual mode and
`demo` for demo mode) and the router sends every read and write -- migrations
included -- to whichever one `ACTIVE_MODE` selects. That means a plain
`manage.py migrate` silently migrates only one of them, leaving the other
behind. The result is confusing failures much later, such as "no such table"
raised from a background scan thread while the migrate output looked successful.

This command applies pending migrations to both aliases and reports the result
per database, so a half-migrated deployment is obvious.
"""

from django.core.management import call_command
from django.core.management.base import BaseCommand
from django.db import connections
from django.db.migrations.executor import MigrationExecutor

import traceback


class Command(BaseCommand):
    help = "Apply migrations to every configured database, not just the active mode's."

    def add_arguments(self, parser):
        parser.add_argument(
            "apps",
            nargs="*",
            help="Restrict to these apps (default: everything).",
        )
        parser.add_argument(
            "--check",
            action="store_true",
            help="Only report which databases have unapplied migrations.",
        )

    def handle(self, *args, **options):
        apps = options.get("apps") or None
        failed = False

        for alias in connections:
            pending = self._pending(alias)
            if not pending:
                self.stdout.write(self.style.SUCCESS(f"{alias}: up to date"))
                continue

            if options["check"]:
                self.stdout.write(
                    self.style.WARNING(f"{alias}: {len(pending)} pending migration(s)")
                )
                continue

            self.stdout.write(f"{alias}: applying {len(pending)} migration(s)...")
            try:
                call_command(
                    "migrate",
                    *(apps or ()),
                    database=alias,
                    interactive=False,
                    verbosity=options.get("verbosity", 1),
                )
            except Exception as exc:  # noqa: BLE001 - report and keep going
                failed = True
                self.stderr.write(self.style.ERROR(f"{alias}: failed - {exc}"))
                # A migration failure is only diagnosable with the traceback. This
                # command deliberately keeps going so one bad database does not
                # hide the state of the other, which is exactly why the traceback
                # has to be printed rather than swallowed.
                self.stderr.write(traceback.format_exc())
                continue

            still = self._pending(alias)
            if still:
                failed = True
                self.stderr.write(
                    self.style.ERROR(f"{alias}: {len(still)} migration(s) still pending")
                )
            else:
                self.stdout.write(self.style.SUCCESS(f"{alias}: up to date"))

        if failed:
            self.stderr.write(
                self.style.ERROR(
                    "One or more databases are not fully migrated. Discovery will fail "
                    "on those until this is resolved."
                )
            )
            raise SystemExit(1)

    @staticmethod
    def _pending(alias: str) -> list[str]:
        try:
            executor = MigrationExecutor(connections[alias])
            targets = executor.loader.graph.leaf_nodes()
            return [
                f"{app_label}.{name}"
                for app_label, name in executor.migration_plan(targets)
            ]
        except Exception:  # noqa: BLE001 - an unmigrated schema is the normal case
            return ["(schema not initialised)"]
