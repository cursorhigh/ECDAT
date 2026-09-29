"""Ad-hoc verification that the audit trail resists tampering.

Not part of the test suite -- this is a one-off probe run against the real
database to confirm the guards actually bite.
"""
import os
import sys

import django

# backend/ (the parent of scratch/) has to be importable for `config.settings`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
django.setup()

from django.db import connection, connections  # noqa: E402
from core.models import AuditLog, WorkSession, log_action  # noqa: E402

db = "default"
results = []


def _update(row, **fields):
    for key, value in fields.items():
        setattr(row, key, value)
    row.save()
    return "updated"


def _sql(statement, params):
    # Must target the SAME database the probe row lives in. Using the default
    # `connection` here would silently report a "bypass" that touched nothing.
    with connections[db].cursor() as cur:
        cur.execute(statement, params)
    return "executed"


def check(label, fn):
    try:
        fn()
        results.append(("TAMPER SUCCEEDED", label, ""))
    except Exception as exc:  # noqa: BLE001
        msg = str(exc).strip().splitlines()[0][:88]
        results.append(("blocked", label, msg))


# Seed one entry to attack.
log_action("system", "tamper probe", "probe", "1", session_id=0)
entry = AuditLog.objects.using(db).order_by("-id").first()
eid = entry.pk
print(f"probe entry id={eid} session_id={entry.session_id} name={entry.session_name!r}")

# 1. ORM update
check("ORM UPDATE via .save()", lambda: _update(entry, message="rewritten"))

# 2. ORM delete
check("ORM DELETE via .delete()", lambda: AuditLog.objects.using(db).filter(pk=eid).delete())

# 3. Raw SQL UPDATE (bypasses the model entirely)
check("raw SQL UPDATE", lambda: _sql(
    "UPDATE core_auditlog SET message='rewritten' WHERE id=%s", [eid]))

# 4. Raw SQL DELETE
check("raw SQL DELETE", lambda: _sql(
    "DELETE FROM core_auditlog WHERE id=%s", [eid]))

# 5. Bulk queryset delete
check("QuerySet .delete() bulk", lambda: AuditLog.objects.using(db).all().delete())

# 6. Raw SQL DELETE everything
check("raw SQL DELETE all rows", lambda: _sql("DELETE FROM core_auditlog", []))

print()
width = 34
for status, label, msg in results:
    print(f"  {status:<24} {label:<{width}} {msg}")

survived = AuditLog.objects.using(db).filter(pk=eid).exists()
untouched = AuditLog.objects.using(db).filter(pk=eid).first()
print()
print(f"  probe entry survived: {survived}")
print(f"  message unchanged:    {untouched.message == 'tamper probe'}")

# 7. Does deleting the session preserve the audit entry?
import uuid  # noqa: E402

session_name = f"probe-session-{uuid.uuid4().hex[:8]}"
sid = WorkSession.objects.using(db).create(name=session_name).pk
log_action("system", "entry that must survive", "probe", "2", session_id=sid)
WorkSession.objects.using(db).filter(pk=sid).delete()
orphan = AuditLog.objects.using(db).filter(target_id="2").order_by("-id").first()
print()
print(f"  audit entry survived session delete: {orphan is not None}")
print(f"  orphaned session_id is NULL:         {orphan is not None and orphan.session_id is None}")
print(
    f"  session_name preserved:              "
    f"{orphan is not None and orphan.session_name == session_name}"
)

# Clean up the probe rows (audit rows cannot be deleted, by design).
print()
print("  note: probe audit rows remain in the DB and cannot be cleaned up -- that is the point.")
