"""Per-connection SQLite tuning.

Django 5.0's plain (non-pooled) SQLite backend only accepts ``timeout`` in
``DATABASES[...]["OPTIONS"]``; ``init_command`` and ``transaction_mode`` are
pooled-backend-only and raise a TypeError here. The pragmas therefore have to be
applied on the ``connection_created`` signal, which fires once per connection.

Why this matters: a multi-source discovery run writes from several scanner
threads against one SQLite file. Without WAL a reader blocks a writer, and
without a busy timeout a blocked writer raises "database is locked" immediately
instead of waiting its turn -- which surfaced as a failed scan.
"""

from django.db.backends.signals import connection_created
from django.dispatch import receiver

# Milliseconds a blocked writer waits before giving up. Matches the 30s
# `timeout` configured in settings so the two do not disagree.
BUSY_TIMEOUT_MS = 30_000


@receiver(connection_created)
def configure_sqlite(sender, connection, **kwargs):
    """Put SQLite into WAL mode with a busy timeout, for this connection only."""
    if connection.vendor != "sqlite":
        return
    try:
        with connection.cursor() as cursor:
            # WAL lets readers run while a writer holds the file. It is a
            # persistent property of the database, so setting it repeatedly is
            # harmless.
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA synchronous=NORMAL;")
            cursor.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS};")
    except Exception:  # noqa: BLE001 - never break a connection over a pragma
        pass
