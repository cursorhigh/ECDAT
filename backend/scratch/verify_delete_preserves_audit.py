"""End-to-end check: delete a real scan, confirm the audit trail survives.

Runs against the demo database. Creates its own session so it never touches
existing data, then deletes it through the same ORM path the HTTP view uses.
"""
import os
import sys
import uuid

import django

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
django.setup()

from core.models import AuditLog, WorkSession, log_action  # noqa: E402

db = "demo"
name = f"e2e-delete-probe-{uuid.uuid4().hex[:8]}"

session = WorkSession.objects.using(db).create(name=name)
sid = session.pk
print(f"created session #{sid} {name!r}")

# Simulate the events a real scan would produce, then the deletion itself.
log_action("scan_created", f"Discovery started for {name!r}", "worksession", str(sid), session_id=sid)
log_action("scan_completed", f"Scan source_code on {name!r} complete: 42 raw findings", "scanjob", "1", session_id=sid)
log_action("scan_deleted", f"Deleted scan {name!r} (#{sid}) and its findings.", "worksession", str(sid), session_id=0, session_name=name)

before = AuditLog.objects.using(db).filter(session_id=sid).count()
print(f"audit rows attached to the session before delete: {before}")

# Exactly what delete_scan_history_session does, minus the other tables.
session.delete()
print("session deleted")

rows = list(
    AuditLog.objects.using(db).filter(session_name=name).order_by("id")
)
print()
print(f"  rows recoverable by session_name: {len(rows)}")
for row in rows:
    print(f"    - {row.action:<14} session_id={row.session_id}  {row.message[:58]}")

deletion_entry = [r for r in rows if r.action == "scan_deleted"]
print()
print(f"  the deletion itself is recorded: {len(deletion_entry) == 1}")
print(f"  all rows detached (session_id NULL): {all(r.session_id is None for r in rows)}")
print(f"  all rows still readable: {len(rows) == before + 1}")
print()
print("  these rows are permanent by design and cannot be cleaned up.")
