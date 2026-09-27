from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'core'

    def ready(self):
        # Registers the connection_created receiver that applies WAL and the
        # busy timeout to every SQLite connection.
        from . import sqlite_pragmas  # noqa: F401
