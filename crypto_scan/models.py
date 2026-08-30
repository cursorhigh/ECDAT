"""Crypto-discovery scan pipeline models.

DB rows are the authoritative source of truth; huey queue state is disposable.

    Scan       one directory scan (path + overall status + timestamps)
    ScanChunk  one slice of the file list, processed by one huey task
"""

from django.db import models


class Scan(models.Model):
    """A single directory scan.

    Status lifecycle: pending -> running -> complete
    (set to 'running' once the first chunk is enqueued; a failed scan may
    transition through has_errors / failed beats via the chunk sweep).
    """

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        COMPLETE = "complete", "Complete"

    path = models.CharField(max_length=4096)
    status = models.CharField(
        max_length=16, choices=Status.choices, default=Status.PENDING
    )
    chunk_count = models.PositiveIntegerField(default=0, help_text="Total number of chunks (N).")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"Scan #{self.pk} {self.path} [{self.status}]"


class ScanChunk(models.Model):
    """One chunk of a scan, processed by one huey task."""

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        DONE = "done", "Done"

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="chunks")
    chunk_id = models.PositiveIntegerField(help_text="0-based chunk index within the scan.")
    status = models.CharField(
        max_length=16, choices=Status.choices, default=Status.PENDING
    )
    results = models.JSONField(default=list, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["chunk_id"]
        constraints = [
            models.UniqueConstraint(
                fields=["scan", "chunk_id"], name="uniq_scan_chunk_id"
            )
        ]

    def __str__(self) -> str:
        return f"Scan {self.scan_id} chunk {self.chunk_id} [{self.status}]"
