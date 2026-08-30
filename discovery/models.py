"""Segment A — Discovery data models.

Models the crypto-discovery pipeline:
    ScanJob -> RawFinding -> NormalizedFinding -> CryptoAsset (+ AssetRelation graph)
"""

from django.db import models

from core.models import Mode, TimeStampedModel


class ScanJob(TimeStampedModel):
    """A single run of a scanner against a target source."""

    class SourceType(models.TextChoices):
        SOURCE_CODE = "source_code", "Source Code Repos"
        BINARY = "binary", "Binary Files"
        DEPENDENCY = "dependency", "Libraries/Dependencies"
        CONTAINER = "container", "Container Images"
        CERTIFICATE = "certificate", "Certificates/PKI"
        HSM = "hsm", "HSM/Key Management"
        CLOUD = "cloud", "Cloud Crypto Services"

    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    source_type = models.CharField(max_length=16, choices=SourceType.choices)
    mode = models.CharField(max_length=8, choices=Mode.choices, default=Mode.ACTUAL)
    target = models.CharField(
        max_length=512,
        help_text="Repo URL, image ref, cert store path, host:port, etc.",
    )
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.QUEUED)
    progress = models.PositiveSmallIntegerField(default=0, help_text="0-100")
    findings_count = models.PositiveIntegerField(default=0)
    error = models.TextField(blank=True, default="")
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    config = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["source_type", "status"]), models.Index(fields=["mode"])]

    def __str__(self) -> str:
        return f"{self.source_type}:{self.target} [{self.status}]"


class RawFinding(TimeStampedModel):
    """A raw, un-normalized finding emitted directly by a scanner."""

    class Status(models.TextChoices):
        NEW = "new", "New"
        NORMALIZED = "normalized", "Normalized"
        IGNORED = "ignored", "Ignored"
        DUP = "duplicate", "Duplicate"

    scan_job = models.ForeignKey(
        ScanJob, on_delete=models.CASCADE, related_name="raw_findings"
    )
    mode = models.CharField(max_length=8, choices=Mode.choices, default=Mode.ACTUAL)
    source_type = models.CharField(max_length=16, choices=ScanJob.SourceType.choices)
    location = models.CharField(max_length=1024, blank=True, default="")
    raw_json = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.NEW)
    ingested_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-ingested_at"]
        indexes = [models.Index(fields=["source_type", "status"]), models.Index(fields=["mode"])]

    def __str__(self) -> str:
        return f"Raw[{self.source_type}] {self.location[:60]}"


class NormalizedFinding(TimeStampedModel):
    """A normalized, deduplicated finding with canonical algorithm fields."""

    class AlgorithmFamily(models.TextChoices):
        RSA = "rsa", "RSA"
        ECC = "ecc", "ECC"
        DSA = "dsa", "DSA"
        DH = "dh", "Diffie-Hellman"
        AES = "aes", "AES"
        HASH = "hash", "Hash"
        MAC = "mac", "MAC"
        PQC = "pqc", "Post-Quantum"
    
        UNKNOWN = "unknown", "Unknown"

    raw_finding = models.OneToOneField(
        RawFinding, on_delete=models.CASCADE, related_name="normalized"
    )
    mode = models.CharField(max_length=8, choices=Mode.choices, default=Mode.ACTUAL)
    family = models.CharField(max_length=16, choices=AlgorithmFamily.choices)
    algorithm = models.CharField(max_length=64, blank=True, default="")
    key_size = models.PositiveIntegerField(null=True, blank=True)
    curve = models.CharField(max_length=64, blank=True, default="")
    protocol = models.CharField(max_length=64, blank=True, default="")
    library = models.CharField(max_length=128, blank=True, default="")
    library_version = models.CharField(max_length=64, blank=True, default="")
    confidence = models.FloatField(default=0.0, help_text="0.0-1.0")
    dedup_key = models.CharField(max_length=128, blank=True, default="")

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.algorithm or self.family} {self.key_size or ''}".strip()


class CryptoAsset(TimeStampedModel):
    """A canonical crypto asset consolidated from one+ normalized findings."""

    class InventoryStatus(models.TextChoices):
        ACTIVE = "active", "Active"
        DORMANT = "dormant", "Dormant"
        REVIEW = "needs_review", "Needs review"

    name = models.CharField(max_length=256)
    mode = models.CharField(max_length=8, choices=Mode.choices, default=Mode.ACTUAL)
    family = models.CharField(max_length=16, choices=NormalizedFinding.AlgorithmFamily.choices)
    algorithm = models.CharField(max_length=64, blank=True, default="")
    key_size = models.PositiveIntegerField(null=True, blank=True)
    curve = models.CharField(max_length=64, blank=True, default="")
    protocol = models.CharField(max_length=64, blank=True, default="")
    library = models.CharField(max_length=128, blank=True, default="")
    library_version = models.CharField(max_length=64, blank=True, default="")
    source_type = models.CharField(max_length=16, choices=ScanJob.SourceType.choices)
    location = models.CharField(max_length=1024, blank=True, default="")
    owner = models.CharField(max_length=128, blank=True, default="")
    inventory_status = models.CharField(
        max_length=16, choices=InventoryStatus.choices, default=InventoryStatus.ACTIVE
    )
    normalized_findings = models.ManyToManyField(NormalizedFinding, related_name="assets")

    class Meta:
        ordering = ["name"]
        indexes = [models.Index(fields=["family"]), models.Index(fields=["source_type"])]

    def __str__(self) -> str:
        return f"{self.name} ({self.algorithm} {self.key_size or ''})".strip()


class AssetRelation(models.Model):
    """An edge in the Crypto Asset Graph: how assets relate to each other."""

    class RelationType(models.TextChoices):
        CONTAINS = "contains", "Contains"
        RELATE = "relate", "Relates to"
        CONTEXT = "context", "Shares context"
        DEPENDS = "depends", "Depends on"

    from_asset = models.ForeignKey(
        CryptoAsset, on_delete=models.CASCADE, related_name="outgoing_relations"
    )
    to_asset = models.ForeignKey(
        CryptoAsset, on_delete=models.CASCADE, related_name="incoming_relations"
    )
    mode = models.CharField(max_length=8, choices=Mode.choices, default=Mode.ACTUAL)
    relation_type = models.CharField(max_length=16, choices=RelationType.choices)
    description = models.CharField(max_length=256, blank=True, default="")

    class Meta:
        unique_together = ("from_asset", "to_asset", "relation_type")

    def __str__(self) -> str:
        return f"{self.from_asset} {self.relation_type} {self.to_asset}"
