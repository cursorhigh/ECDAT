"""Create, list and revoke ECDAT API keys.

    manage.py create_api_key "ci pipeline"
    manage.py create_api_key --list
    manage.py create_api_key --revoke <prefix>
"""

from django.core.management.base import BaseCommand, CommandError

from core.api import create_api_key
from core.modes import active_db, active_mode
from core.models import ApiKey


class Command(BaseCommand):
    help = "Manage ECDAT API keys (create / list / revoke)."

    def add_arguments(self, parser):
        parser.add_argument("name", nargs="?", help="Human label for the new key.")
        parser.add_argument("--scopes", default="", help="Comma-separated scopes (optional).")
        parser.add_argument("--list", action="store_true", help="List existing keys.")
        parser.add_argument("--revoke", metavar="PREFIX", help="Revoke the key with this prefix.")

    def handle(self, *args, **options):
        db = active_db()
        self.stdout.write(f"Database: {db} (mode={active_mode()})")

        if options["list"]:
            keys = ApiKey.objects.using(db).all()
            if not keys:
                self.stdout.write("No API keys yet.")
                return
            for key in keys:
                state = "active" if key.is_active else "revoked"
                used = key.last_used_at.isoformat() if key.last_used_at else "never"
                self.stdout.write(
                    f"  {key.prefix:<14} {state:<8} last_used={used:<26} {key.name}"
                )
            return

        if options["revoke"]:
            updated = ApiKey.objects.using(db).filter(prefix=options["revoke"]).update(is_active=False)
            if not updated:
                raise CommandError(f"No API key with prefix {options['revoke']!r}.")
            self.stdout.write(self.style.SUCCESS(f"Revoked key {options['revoke']}."))
            return

        name = options["name"]
        if not name:
            raise CommandError("Provide a name, or use --list / --revoke.")

        instance, full_key = create_api_key(name, scopes=options["scopes"], db=db)
        self.stdout.write(self.style.SUCCESS("API key created. Store it now - it is not shown again."))
        self.stdout.write("")
        self.stdout.write(f"  name    : {instance.name}")
        self.stdout.write(f"  prefix  : {instance.prefix}")
        self.stdout.write(f"  key     : {full_key}")
        self.stdout.write("")
        self.stdout.write("Send it as:  X-API-Key: <key>")
