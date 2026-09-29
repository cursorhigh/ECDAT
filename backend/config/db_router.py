"""ECDAT database router.

There is a single database, so this router exists for one reason: to make that
explicit and to keep `allow_migrate` honest about where the schema lives.

Before demo mode was removed it routed every operation to whichever of two
databases `ECDAT_ACTIVE_MODE` selected. Both branches collapsed to `default`
once the `demo` alias went away, so it is left in place rather than removed --
dropping `DATABASE_ROUTERS` would silently change which database Django picks
for any app not covered by an explicit `using()`, and that is not a risk worth
taking to tidy one file.
"""

from core.modes import ACTUAL_DB


class ECDATRouter:
    """Route every model operation to the single database."""

    def db_for_read(self, model, **hints):
        return ACTUAL_DB

    def db_for_write(self, model, **hints):
        return ACTUAL_DB

    def allow_relation(self, obj1, obj2, **hints):
        return True

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        # The schema lives in one place. Returning True for `demo` used to be
        # what kept the second database migrated; with that alias gone this is
        # the only database the schema may be applied to.
        return db == ACTUAL_DB
