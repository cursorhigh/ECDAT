"""
Drops the `mode` column and its indexes.

Demo mode is removed. `mode` existed to label rows as synthetic (demo) or real
(actual) and to pair with the second `demo` database that enforced the split at
the schema level. With one database and no demo boundary, the column was always
"actual" and asserted nothing -- it was a label that could disagree with the
database it sat in, which is worse than having no label at all.

The values are discarded rather than migrated: no code path reads this column
any more, so preserving "actual" on every row would be dead data.

The three-step shape is forced by SQLite. The append-only triggers from 0007
compare `NEW.mode IS OLD.mode`, and SQLite refuses `ALTER TABLE ... DROP COLUMN`
while any trigger still references the column -- it reports
"error in trigger core_auditlog_block_update after drop column". So the triggers
are dropped, the column removed, and the triggers recreated without the mode
comparison. The immutability guarantee is unchanged: every other column is still
compared, and the DELETE guard is untouched.
"""

from django.db import migrations

DROP_AUDIT_TRIGGERS = """
DROP TRIGGER IF EXISTS core_auditlog_block_update;
DROP TRIGGER IF EXISTS core_auditlog_block_delete;
"""

# Identical to 0007's trigger apart from the removed `NEW.mode IS OLD.mode`
# line, so detaching a deleted session's audit entries still works and every
# other column remains protected.
CREATE_AUDIT_TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS core_auditlog_block_update
BEFORE UPDATE ON core_auditlog
WHEN NOT (
        OLD.session_id IS NOT NULL
    AND NEW.session_id IS NULL
    AND NEW.action       IS OLD.action
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
        ("core", "0007_auditlog_allow_session_detach"),
    ]

    operations = [
        migrations.RunSQL(
            sql=DROP_AUDIT_TRIGGERS,
            reverse_sql="",
        ),
        migrations.RemoveField(
            model_name="auditlog",
            name="mode",
        ),
        migrations.RunSQL(
            sql=CREATE_AUDIT_TRIGGERS,
            reverse_sql=DROP_AUDIT_TRIGGERS,
        ),
    ]
