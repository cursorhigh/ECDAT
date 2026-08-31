from django.db import models

from core.models import Mode, TimeStampedModel


class MitigationPlan(TimeStampedModel):
    """A prioritized remediation / migration plan for one completed analysis run."""

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        GENERATING = "generating", "Generating"
        COMPLETE = "complete", "Complete"
        FAILED = "failed", "Failed"

    run = models.OneToOneField(
        "analysis.AnalysisRun",
        on_delete=models.CASCADE,
        related_name="mitigation_plan",
        help_text="The completed analysis run this plan is derived from.",
    )
    mode = models.CharField(max_length=8, choices=Mode.choices, default=Mode.ACTUAL)
    session = models.ForeignKey(
        "core.WorkSession",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="mitigation_plans",
        help_text="Work session this plan belongs to (null = global).",
    )
    status = models.CharField(
        max_length=16, choices=Status.choices, default=Status.PENDING
    )
    progress = models.PositiveSmallIntegerField(default=0, help_text="0-100")
    document = models.JSONField(default=dict, blank=True)
    error = models.TextField(blank=True, default="")
    generated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["status"]), models.Index(fields=["mode"])]

    def __str__(self) -> str:
        return f"{self.run} [{self.status}]"