from django.db import models

from core.models import Mode, TimeStampedModel


class AnalysisRun(TimeStampedModel):
    class Status(models.TextChoices):
        AWAITING_CONTEXT = "awaiting_context", "Awaiting context"
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    scan_job = models.ForeignKey(
        "discovery.ScanJob", on_delete=models.CASCADE, related_name="analysis_runs"
    )
    mode = models.CharField(max_length=8, choices=Mode.choices, default=Mode.ACTUAL)
    session = models.ForeignKey(
        "core.WorkSession",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="analysis_runs",
        help_text="Work session this analysis run belongs to (null = global).",
    )
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.QUEUED)
    progress = models.PositiveSmallIntegerField(default=0, help_text="0-100")
    repository = models.JSONField(default=dict, blank=True)
    raw_system_context = models.JSONField(default=dict, blank=True)
    input_payload = models.JSONField(default=dict, blank=True)
    cbom_document = models.JSONField(default=dict, blank=True)
    risk_context = models.JSONField(default=dict, blank=True)
    executive_summary = models.JSONField(default=dict, blank=True)
    error = models.TextField(blank=True, default="")
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    await_until = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Deadline for the awaiting-context auto-analysis prompt (default context fires after it).",
    )

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["status"]), models.Index(fields=["mode"])]

    def __str__(self) -> str:
        return f"{self.scan_job} [{self.status}]"


class AssetAssessment(TimeStampedModel):
    run = models.ForeignKey(AnalysisRun, on_delete=models.CASCADE, related_name="assessments")
    mode = models.CharField(max_length=8, choices=Mode.choices, default=Mode.ACTUAL)
    session = models.ForeignKey(
        "core.WorkSession",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="asset_assessments",
        help_text="Work session this assessment belongs to (null = global).",
    )
    asset = models.ForeignKey(
        "discovery.CryptoAsset",
        on_delete=models.CASCADE,
        related_name="assessments",
        null=True,
        blank=True,
    )
    finding_ref = models.CharField(max_length=128, blank=True, default="")
    cbom_asset = models.JSONField(default=dict, blank=True)
    hndl_result = models.JSONField(default=dict, blank=True)
    mosca_result = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["id"]
        indexes = [
            models.Index(fields=["run"]),
            models.Index(fields=["mode"]),
            models.Index(fields=["finding_ref"]),
        ]

    def __str__(self) -> str:
        return f"{self.run_id}:{self.finding_ref}"
