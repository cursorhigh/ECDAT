"""Shared models for ECDAT.

Contains a common timestamped base model and the audit log used to track
key user actions across the application (run scans, ingest findings, export
data, merge/delete assets, etc.).
"""

from django.conf import settings
from django.db import models


class Mode(models.TextChoices):
    """Whether a record belongs to demo (synthetic) or actual (real) data.

    The database each row lives in is the hard boundary; this field is kept
    on rows as a safety label/assertion.
    """

    DEMO = "demo", "Demo"
    ACTUAL = "actual", "Actual"


class TimeStampedModel(models.Model):
    """Abstract base adding created_at / updated_at to any model."""

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class WorkSession(models.Model):
    """A named workspace that isolates all ECDAT data layers.

    Every data model (discovery, inventory, graph, analysis, audit) carries a
    nullable `session` FK. Rows written outside any session (or before this
    feature existed) keep `session=NULL` = "global"; they are only shown in the
    dashboard's "All data" switcher mode. Switching to a session filters every
    layer to that session's rows only.
    """

    name = models.CharField(max_length=128, unique=True)
    description = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Work session"

    def __str__(self) -> str:
        return self.name


class AuditLog(models.Model):
    """Append-only audit trail of key user / system actions."""

    class Action(models.TextChoices):
        SCAN_CREATED = "scan_created", "Scan created"
        SCAN_COMPLETED = "scan_completed", "Scan completed"
        FINDINGS_INGESTED = "findings_ingested", "Findings ingested"
        ASSET_MERGED = "asset_merged", "Asset merged"
        ASSET_DELETED = "asset_deleted", "Asset deleted"
        EXPORT = "export", "Export generated"
        DEMO_SEEDED = "demo_seeded", "Demo data seeded"
        SYSTEM = "system", "System event"

    action = models.CharField(max_length=32, choices=Action.choices)
    mode = models.CharField(max_length=8, choices=Mode.choices, default=Mode.ACTUAL)
    session = models.ForeignKey(
        WorkSession,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="audit_logs",
        help_text="Work session this audit entry belongs to (null = global).",
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="audit_logs",
        help_text="User who performed the action (null = system/automated).",
    )
    target_type = models.CharField(max_length=64, blank=True, default="")
    target_id = models.CharField(max_length=64, blank=True, default="")
    message = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["action", "created_at"])]

    def __str__(self) -> str:
        return f"{self.created_at:%Y-%m-%d %H:%M} {self.action} {self.target_type} {self.target_id}"


def log_action(action: str, message: str = "", target_type: str = "", target_id: str = "", actor=None, mode=None, session_id=None):
    """Convenience helper to write an audit entry synchronously.

    The row is written to the database that belongs to `mode`, so the row's
    mode field always agrees with the DB it lands in. `session_id` scopes the
    entry to a work session; when omitted it falls back to the thread-local
    session captured by WorkSessionMiddleware (i.e. whatever workspace the
    request was viewing).
    """
    if mode is None:
        from .modes import active_mode

        mode = active_mode()
    from .modes import db_alias_for_mode

    db = db_alias_for_mode(mode)
    if session_id is None:
        from .sessions import thread_session_id

        session_id = thread_session_id() or None
    AuditLog.objects.using(db).create(
        action=action,
        mode=mode,
        session_id=session_id or None,
        actor=actor,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else "",
        message=message,
    )
