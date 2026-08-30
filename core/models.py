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


def log_action(action: str, message: str = "", target_type: str = "", target_id: str = "", actor=None, mode=None):
    """Convenience helper to write an audit entry synchronously."""
    if mode is None:
        from .modes import active_mode

        mode = active_mode()
    AuditLog.objects.create(
        action=action,
        mode=mode,
        actor=actor,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else "",
        message=message,
    )
