"""ECDAT database router.

Routes every read/write/migration to one of two databases selected by the
active mode (hard demo/actual data boundary):

- ACTIVE_MODE == 'demo'  -> all operations on the `demo` database
- ACTIVE_MODE == 'actual'-> all operations on the `default` database

Each database is a fully self-contained copy of the schema so relations
(including the AuditLog -> User FK) always resolve within one database and
demo data can never spill into actual data (or vice-versa).
"""

from core.modes import active_db


class ECDATRouter:
    """Route all model operations to the active mode's database.

    The `crypto_scan` app is exempt: it represents real scan/report data and
    always lives on the `default` database regardless of demo/actual mode.
    """

    # App labels that bypass the demo/actual split and always use `default`.
    ALWAYS_DEFAULT_APPS = {"crypto_scan"}

    def _alias(self, model=None):
        if model is not None and model._meta.app_label in self.ALWAYS_DEFAULT_APPS:
            return "default"
        return active_db()

    def db_for_read(self, model, **hints):
        return self._alias(model)

    def db_for_write(self, model, **hints):
        return self._alias(model)

    def allow_relation(self, obj1, obj2, **hints):
        return True

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        # crypto_scan always migrates to `default` only.
        if app_label in self.ALWAYS_DEFAULT_APPS:
            return db == "default"
        # Run migrations on both databases so either mode is self-contained.
        return db in ("default", "demo")
