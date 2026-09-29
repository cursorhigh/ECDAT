"""Narrow the audit UPDATE trigger to permit only the session-detach.

0005 installed a blanket ``BEFORE UPDATE ... RAISE(ABORT)`` guard. That was too
broad: deleting a WorkSession makes Django's collector issue ``UPDATE
core_auditlog SET session_id = NULL`` (the ``SET_NULL`` on_delete from 0005),
which the blanket trigger rejected -- so deleting a scan raised IntegrityError
instead of preserving its audit history.

A trail that cannot survive the deletion of the thing it documents is not
immutable, it is just broken. So the UPDATE guard now allows exactly one
transition: detaching an entry from a session that no longer exists, with every
other column provably unchanged. Any attempt to rewrite the action, message,
target, actor, mode, session name or timestamp still aborts.
"""

from django.db import migrations


DROP_OLD_TRIGGERS = """
DROP TRIGGER IF EXISTS core_auditlog_block_update;
DROP TRIGGER IF EXISTS core_auditlog_block_delete;
"""

# `WHEN NOT (...)` means: fire the ABORT unless this is precisely the detach.
# Each column is compared with IS so that a NULL on both sides still matches,
# which keeps the detach working for global (session-less) entries.
CREATE_NARROWED_TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS core_auditlog_block_update
BEFORE UPDATE ON core_auditlog
WHEN NOT (
        OLD.session_id IS NOT NULL
    AND NEW.session_id IS NULL
    AND NEW.action       IS OLD.action
    AND NEW.mode         IS OLD.mode
    AND NEW.session_name IS OLD.session_name
    AND NEW.actor_id     IS OLD.actor_id
    AND NEW.target_type  IS OLD.target_type
    AND NEW.target_id    IS OLD.target_id
    AND NEW.message      IS OLD.message
    AND NEW.created_at   IS OLD.created_at
)
BEGIN
    SELECT RAISE(ABORT, 'audit trail is append-only: audit entries cannot be modified');
END;

CREATE TRIGGER IF NOT EXISTS core_auditlog_block_delete
BEFORE DELETE ON core_auditlog
BEGIN
    SELECT RAISE(ABORT, 'audit trail is append-only: audit entries cannot be deleted');
END;
"""


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0006_alter_auditlog_action"),
    ]

    operations = [
        migrations.RunSQL(
            sql=DROP_OLD_TRIGGERS + CREATE_NARROWED_TRIGGERS,
            reverse_sql=DROP_OLD_TRIGGERS,
        ),
    ]
