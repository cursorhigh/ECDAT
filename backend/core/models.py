"""Shared models for ECDAT.

Contains a common timestamped base model and the audit log used to track
key user actions across the application (run scans, ingest findings, export
data, merge/delete assets, etc.).
"""

from django.conf import settings
from django.db import models


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
        SCAN_DELETED = "scan_deleted", "Scan deleted"
        EXPORT = "export", "Export generated"
        SYSTEM = "system", "System event"

    action = models.CharField(max_length=32, choices=Action.choices)
    session = models.ForeignKey(
        WorkSession,
        null=True,
        blank=True,
        # SET_NULL, not CASCADE. A deleted scan must not take its own audit
        # history with it -- that would make erasing the evidence the default
        # way to deal with a scan you dislike. The row survives with a null
        # session and stays readable via `session_name`.
        on_delete=models.SET_NULL,
        related_name="audit_logs",
        help_text=(
            "Work session this audit entry belongs to. Nulled (never cascaded) "
            "when the session is deleted, so the entry outlives its session."
        ),
    )
    # Denormalised snapshot of the session name. The FK above is deliberately
    # severable; this field is what keeps the entry self-describing afterwards.
    session_name = models.CharField(
        max_length=128,
        blank=True,
        default="",
        help_text="Session name captured at write time; survives session deletion.",
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
        indexes = [
            models.Index(fields=["action", "created_at"]),
            models.Index(fields=["session_name"], name="core_auditlog_sessname_idx"),
        ]

    def save(self, *args, **kwargs):
        """Refuse edits to an existing entry.

        Audit rows are append-only. This is the application-level half of that
        guarantee; migration 0005 adds the database-level half, so a row is
        immutable even against a raw SQL UPDATE from outside the ORM.
        """
        if not self._state.adding:
            raise ValueError(
                "AuditLog rows are append-only and cannot be modified. "
                "Write a new entry instead."
            )
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError(
            "AuditLog rows are append-only and cannot be deleted. "
            "Deleting the audited object does not remove its history."
        )

    def __str__(self) -> str:
        return f"{self.created_at:%Y-%m-%d %H:%M} {self.action} {self.target_type} {self.target_id}"


class ApiKey(models.Model):
    """A named API credential for programmatic access to the ECDAT API.

    The plaintext key is only ever shown once, at creation time. Only a
    SHA-256 hash of the secret part is stored, alongside a short public
    ``prefix`` used to look the row up without scanning every key.
    """

    name = models.CharField(max_length=128)
    prefix = models.CharField(max_length=16, unique=True, db_index=True)
    hashed_key = models.CharField(max_length=64)
    is_active = models.BooleanField(default=True)
    scopes = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="Optional comma-separated scope list (empty = full access).",
    )
    last_used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "API key"
        verbose_name_plural = "API keys"

    def __str__(self) -> str:
        state = "active" if self.is_active else "revoked"
        return f"{self.name} ({self.prefix}…, {state})"

    @property
    def masked(self) -> str:
        return f"{self.prefix}…"


def log_action(action: str, message: str = "", target_type: str = "", target_id: str = "", actor=None, session_id=None, session_name=None):
    """Convenience helper to write an audit entry synchronously.

    `session_id` scopes the entry to a work session; when omitted it falls back
    to the thread-local session captured by WorkSessionMiddleware (i.e. whatever
    workspace the request was viewing).

    `session_name` overrides the name snapshot. Pass it when the session is
    being deleted or has already gone, because looking the name up by id would
    then fail and the entry would be left unattributable.
    """
    from .modes import active_db

    db = active_db()
    if session_id is None:
        from .sessions import thread_session_id

        session_id = thread_session_id() or None

    # Snapshot the session name now, while the session still exists. Deleting a
    # scan severs the FK (SET_NULL) but must not make the entry unreadable.
    if session_name is None:
        session_name = ""
        if session_id:
            session_name = (
                WorkSession.objects.using(db)
                .filter(pk=session_id)
                .values_list("name", flat=True)
                .first()
                or ""
            )

    AuditLog.objects.using(db).create(
        action=action,
        session_id=session_id or None,
        session_name=session_name,
        actor=actor,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else "",
        message=message,
    )
