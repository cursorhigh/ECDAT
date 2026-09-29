"""Make the audit trail append-only at both the schema and the storage layer.

Three parts:

1. ``AuditLog.session`` moves from CASCADE to SET_NULL. Deleting a scan used to
   destroy the evidence of that scan, which made "delete it" the easiest way to
   erase a trail. The entry now outlives its session.
2. ``AuditLog.session_name`` snapshots the session name at write time, because
   (1) deliberately severs the FK and the entry still has to be readable.
3. SQLite triggers that ABORT any UPDATE or DELETE against the audit table.

(3) is the part that matters for tamper-resistance. The model-level guards in
``AuditLog.save``/``AuditLog.delete`` stop ORM writes, and the removal of the
explicit ``AuditLog...delete()`` calls in ``core.views`` stops the app from
deleting rows. Neither protects against a raw ``DELETE FROM core_auditlog`` run
against the database file. These triggers do.

Every ``log_action`` call is an INSERT, so the triggers do not affect normal
operation. The app's test suite uses only ``django.test.TestCase``, which rolls
back rather than truncating, so teardown never trips the delete trigger either.
"""

from django.db import migrations, models
import django.db.models.deletion


# Applied after the FK alter so the column exists. Guarded with IF NOT EXISTS so
# the migration is re-runnable against a database that already has them.
CREATE_AUDIT_IMMUTABILITY_TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS core_auditlog_block_update
BEFORE UPDATE ON core_auditlog
BEGIN
    SELECT RAISE(ABORT, 'audit trail is append-only: audit entries cannot be modified');
END;

CREATE TRIGGER IF NOT EXISTS core_auditlog_block_delete
BEFORE DELETE ON core_auditlog
BEGIN
    SELECT RAISE(ABORT, 'audit trail is append-only: audit entries cannot be deleted');
END;
"""

DROP_AUDIT_IMMUTABILITY_TRIGGERS = """
DROP TRIGGER IF EXISTS core_auditlog_block_update;
DROP TRIGGER IF EXISTS core_auditlog_block_delete;
"""


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0004_apikey"),
    ]

    operations = [
        migrations.AlterField(
            model_name="auditlog",
            name="session",
            field=models.ForeignKey(
                blank=True,
                help_text=(
                    "Work session this audit entry belongs to. Nulled (never cascaded) "
                    "when the session is deleted, so the entry outlives its session."
                ),
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="audit_logs",
                to="core.worksession",
            ),
        ),
        migrations.AddField(
            model_name="auditlog",
            name="session_name",
            field=models.CharField(
                blank=True,
                default="",
                help_text="Session name captured at write time; survives session deletion.",
                max_length=128,
            ),
        ),
        migrations.AddIndex(
            model_name="auditlog",
            index=models.Index(
                fields=["session_name"], name="core_auditlog_sessname_idx"
            ),
        ),
        migrations.RunSQL(
            sql=CREATE_AUDIT_IMMUTABILITY_TRIGGERS,
            reverse_sql=DROP_AUDIT_IMMUTABILITY_TRIGGERS,
        ),
    ]
