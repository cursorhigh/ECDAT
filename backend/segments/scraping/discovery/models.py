"""Segment A — Discovery data models.

Models the crypto-discovery pipeline:
    ScanJob -> RawFinding -> NormalizedFinding -> CryptoAsset (+ AssetRelation graph)
"""

from django.db import models

from core.models import TimeStampedModel


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
        VALIDATING = "validating", "Validating"
        RUNNING = "running", "Running"
        CANCELLING = "cancelling", "Cancelling"
        COMPLETED = "completed", "Completed"
        # Succeeded technically but coverage was incomplete (unreadable files,
        # unsupported formats, insufficient permissions, timeouts).
        PARTIAL = "partial", "Partial"
        FAILED = "failed", "Failed"
        CANCELLED = "cancelled", "Cancelled"

    source_type = models.CharField(max_length=16, choices=SourceType.choices)
    session = models.ForeignKey(
        "core.WorkSession",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="scan_jobs",
        help_text="Work session this scan belongs to (null = global).",
    )
    target = models.CharField(
        max_length=512,
        help_text="Repo URL, image ref, cert store path, host:port, etc.",
    )
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.QUEUED)
    progress = models.PositiveSmallIntegerField(default=0, help_text="0-100")
    findings_count = models.PositiveIntegerField(default=0)
    error = models.TextField(blank=True, default="")

    # --- measured progress (never a fixed ladder) --------------------------
    progress_stage = models.CharField(
        max_length=32,
        blank=True,
        default="",
        help_text="Current phase, e.g. enumerating/inspecting/persisting/correlating.",
    )
    items_total = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="Items discovered to inspect; null when not yet known.",
    )
    items_scanned = models.PositiveIntegerField(default=0)
    items_skipped = models.PositiveIntegerField(default=0)
    skip_reasons = models.JSONField(
        default=dict,
        blank=True,
        help_text=(
            "Per-reason breakdown of skipped items, e.g. "
            "{'unreadable': 3, 'unrecognised_format': 1}. Explains why a scan "
            "reported partial coverage."
        ),
    )

    # --- structured failure detail ----------------------------------------
    error_code = models.CharField(max_length=48, blank=True, default="")
    error_scope = models.CharField(max_length=64, blank=True, default="")
    error_recoverable = models.BooleanField(null=True, blank=True)
    error_action = models.CharField(max_length=200, blank=True, default="")

    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    config = models.JSONField(default=dict, blank=True)
    batch = models.ForeignKey(
        # String reference: ScanBatch is defined below and points back here.
        "ScanBatch",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="jobs",
        help_text="Parent run when this job is one source of a multi-source scan.",
    )

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["source_type", "status"])]

    def __str__(self) -> str:
        return f"{self.source_type}:{self.target} [{self.status}]"


class ScanBatch(TimeStampedModel):
    """One user-initiated discovery run across several sources.

    A ScanJob covers exactly one source, because that is what a scanner is and
    what a finding is attributed to. When a user asks for "everything", the
    work is fanned out into one ScanJob per source and this row is the parent
    that presents them as a single operation.

    The batch stores no findings of its own; its status and progress are always
    derived from its children so the two can never disagree.
    """

    target = models.CharField(max_length=512)
    scan_type = models.CharField(max_length=16, default="specified")
    source_types = models.JSONField(
        default=list,
        blank=True,
        help_text="The sources the user asked for, in the order they were listed.",
    )
    excluded = models.JSONField(
        default=list,
        blank=True,
        help_text=(
            "Sources that were not run, with the reason, e.g. "
            "[{'source': 'binary', 'reason': 'needs a folder target'}]."
        ),
    )
    status = models.CharField(max_length=16, choices=ScanJob.Status.choices, default=ScanJob.Status.QUEUED)
    progress = models.PositiveSmallIntegerField(default=0)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    session = models.ForeignKey(
        "core.WorkSession",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="scan_batches",
    )

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["status"])]

    def __str__(self) -> str:
        return f"batch:{self.target} [{len(self.source_types or [])} sources, {self.status}]"


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
    session = models.ForeignKey(
        "core.WorkSession",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="raw_findings",
        help_text="Work session this finding belongs to (null = global).",
    )
    source_type = models.CharField(max_length=16, choices=ScanJob.SourceType.choices)
    location = models.CharField(
        max_length=1024,
        blank=True,
        default="",
        help_text=(
            "Human-readable location shown in the UI. In a quick or whole scan "
            "this is a profile label such as 'WORKSPACE/package.json', not a "
            "filesystem path."
        ),
    )
    source_path = models.CharField(
        max_length=1024,
        blank=True,
        default="",
        help_text=(
            "Absolute filesystem path the scanner actually read. Lets post-ingest "
            "steps re-open the artefact without guessing from the display label."
        ),
    )
    raw_json = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.NEW)
    ingested_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-ingested_at"]
        indexes = [models.Index(fields=["source_type", "status"])]

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
        DES3 = "des3", "DES/Triple DES"
        HASH = "hash", "Hash"
        MAC = "mac", "MAC"
        PQC = "pqc", "Post-Quantum"
        UNKNOWN = "unknown", "Unknown"

    class FindingKind(models.TextChoices):
        """What kind of cryptographic artefact a finding describes.

        Not every finding is an algorithm: discovery must also be able to say
        "this is a certificate", "this is a key reference", "this is a
        protocol" without collapsing them all into one algorithm family.
        """

        ALGORITHM = "algorithm", "Algorithm"
        KEY = "key", "Key"
        CERTIFICATE = "certificate", "Certificate"
        PROTOCOL = "protocol", "Protocol"
        LIBRARY = "library", "Library"
        DEPENDENCY = "dependency", "Dependency"
        CRYPTO_API = "crypto_api", "Crypto API"
        CRYPTO_CONFIG = "crypto_configuration", "Crypto configuration"
        KEY_REFERENCE = "key_reference", "Key reference"
        HARDWARE_MODULE = "hardware_module", "Hardware module"
        CLOUD_SERVICE = "cloud_crypto_service", "Cloud crypto service"
        CONTAINER = "container", "Container image"
        UNKNOWN = "unknown_crypto_artifact", "Unknown artefact"

    raw_finding = models.OneToOneField(
        RawFinding, on_delete=models.CASCADE, related_name="normalized"
    )
    session = models.ForeignKey(
        "core.WorkSession",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="normalized_findings",
        help_text="Work session this finding belongs to (null = global).",
    )
    kind = models.CharField(
        max_length=32,
        choices=FindingKind.choices,
        default=FindingKind.ALGORITHM,
        help_text="Category of cryptographic artefact observed.",
    )
    family = models.CharField(max_length=16, choices=AlgorithmFamily.choices)
    algorithm = models.CharField(max_length=64, blank=True, default="")
    key_size = models.PositiveIntegerField(null=True, blank=True)
    curve = models.CharField(max_length=64, blank=True, default="")
    protocol = models.CharField(max_length=64, blank=True, default="")
    library = models.CharField(max_length=128, blank=True, default="")
    library_version = models.CharField(max_length=64, blank=True, default="")
    confidence = models.FloatField(default=0.0, help_text="0.0-1.0")
    dedup_key = models.CharField(max_length=128, blank=True, default="")
    line = models.PositiveIntegerField(
        null=True, blank=True, help_text="Line within the located file, when known."
    )
    evidence = models.JSONField(
        default=dict,
        blank=True,
        help_text="Why ECDAT believes this exists. Never contains secret material.",
    )

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

    class AssetType(models.TextChoices):
        """What kind of thing this asset is.

        Deliberately not an algorithm family: an asset is the *thing* that
        carries cryptography (an application, a binary, a certificate, a
        container), while `family` describes the cryptography observed on it.
        The taxonomy is open-ended so a new scanner can add a type without a
        schema change to every consumer.
        """

        APPLICATION = "application", "Application"
        REPOSITORY = "repository", "Repository"
        SOURCE_CODE = "source_code", "Source code"
        BINARY = "binary", "Binary"
        FIRMWARE = "firmware", "Firmware"
        CONTAINER = "container", "Container"
        LIBRARY = "library", "Library"
        DEPENDENCY = "dependency", "Dependency"
        CERTIFICATE = "certificate", "Certificate"
        KEY_REFERENCE = "key_reference", "Key reference"
        CLOUD_RESOURCE = "cloud_resource", "Cloud resource"
        INFRASTRUCTURE = "infrastructure", "Infrastructure"
        HARDWARE = "hardware", "Hardware"
        NETWORK_ENDPOINT = "network_endpoint", "Network endpoint"
        EXTERNAL_SERVICE = "external_service", "External service"
        API = "api", "API"
        UNKNOWN = "unknown", "Unknown"

    name = models.CharField(max_length=256)
    session = models.ForeignKey(
        "core.WorkSession",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="crypto_assets",
        help_text="Work session this asset belongs to (null = global).",
    )
    asset_type = models.CharField(
        max_length=32,
        choices=AssetType.choices,
        default=AssetType.UNKNOWN,
        help_text="Category of the thing carrying this cryptography.",
    )
    identifier = models.CharField(
        max_length=64,
        blank=True,
        default="",
        help_text="Stable content-derived identity for this artefact.",
    )
    environment = models.CharField(
        max_length=64,
        blank=True,
        default="",
        help_text="Deployment environment when the scanner can determine it.",
    )
    family = models.CharField(max_length=16, choices=NormalizedFinding.AlgorithmFamily.choices)
    algorithm = models.CharField(max_length=64, blank=True, default="")
    key_size = models.PositiveIntegerField(null=True, blank=True)
    curve = models.CharField(max_length=64, blank=True, default="")
    protocol = models.CharField(max_length=64, blank=True, default="")
    library = models.CharField(max_length=128, blank=True, default="")
    library_version = models.CharField(max_length=64, blank=True, default="")
    source_type = models.CharField(max_length=16, choices=ScanJob.SourceType.choices)
    location = models.CharField(
        max_length=1024,
        blank=True,
        default="",
        help_text="Display label for the place this asset was seen.",
    )
    source_path = models.CharField(
        max_length=1024,
        blank=True,
        default="",
        help_text="Absolute path the asset was read from, when read from disk.",
    )
    owner = models.CharField(max_length=128, blank=True, default="")
    inventory_status = models.CharField(
        max_length=16, choices=InventoryStatus.choices, default=InventoryStatus.ACTIVE
    )
    normalized_findings = models.ManyToManyField(NormalizedFinding, related_name="assets")

    class Meta:
        ordering = ["name"]
        indexes = [
            models.Index(fields=["family"]),
            models.Index(fields=["source_type"]),
            models.Index(fields=["asset_type"]),
        ]

    def __str__(self) -> str:
        return f"{self.name} ({self.algorithm} {self.key_size or ''})".strip()


class AssetOccurrence(models.Model):
    """One sighting of an asset, distinct from the asset's identity.

    The plan is explicit that an artefact and its occurrences are different
    things: one RSA implementation used in twenty applications is *one*
    artefact with twenty occurrences, not twenty artefacts. Collapsing those
    is what made asset metadata write-once and lost the second sighting
    entirely.
    """

    asset = models.ForeignKey(
        CryptoAsset, on_delete=models.CASCADE, related_name="occurrences"
    )
    scan_job = models.ForeignKey(
        ScanJob,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="asset_occurrences",
    )
    finding = models.ForeignKey(
        NormalizedFinding,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="occurrences",
    )
    location = models.CharField(max_length=1024, blank=True, default="")
    line = models.PositiveIntegerField(null=True, blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    evidence = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-last_seen"]
        indexes = [models.Index(fields=["asset", "location"])]

    def __str__(self) -> str:
        return f"{self.asset} @ {self.location}"


class Dependency(TimeStampedModel):
    """A declared dependency with its cryptographic relevance.

    A dependency is a first-class discovery fact, not just a finding string:
    knowing *which* version of a crypto library an application pulls in, and
    whether it is a runtime or test-only dependency, is what makes the later
    CBOM and migration reasoning possible.
    """

    class Scope(models.TextChoices):
        RUNTIME = "runtime", "Runtime"
        DEVELOPMENT = "development", "Development"

    class Relevance(models.TextChoices):
        CORE = "core", "Core crypto"
        SUPPORTING = "supporting", "Supporting"
        ADJACENT = "adjacent", "Adjacent"
        MANAGED_KEY_SERVICE = "managed_key_service", "Managed key service"
        POST_QUANTUM = "post_quantum", "Post-quantum"

    session = models.ForeignKey(
        "core.WorkSession",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="dependencies",
        help_text="Work session this dependency belongs to (null = global).",
    )
    scan_job = models.ForeignKey(
        ScanJob,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="dependencies",
        help_text="Scan that discovered this dependency.",
    )
    package = models.CharField(max_length=256)
    version = models.CharField(max_length=64, blank=True, default="")
    ecosystem = models.CharField(max_length=32, blank=True, default="")
    scope = models.CharField(max_length=16, choices=Scope.choices, default=Scope.RUNTIME)
    is_crypto = models.BooleanField(default=False)
    relevance = models.CharField(max_length=32, choices=Relevance.choices, blank=True, default="")
    capability = models.CharField(max_length=64, blank=True, default="")
    key_service = models.CharField(
        max_length=32, blank=True, default="", help_text="Managed key service, e.g. aws/azure."
    )
    family = models.CharField(max_length=16, choices=NormalizedFinding.AlgorithmFamily.choices, default="unknown")
    location = models.CharField(
        max_length=1024,
        blank=True,
        default="",
        help_text="Display label of the manifest this came from.",
    )
    source_path = models.CharField(
        max_length=1024,
        blank=True,
        default="",
        help_text="Absolute path of the manifest, used to locate lock files beside it.",
    )
    evidence = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["package", "version"]
        indexes = [
            models.Index(fields=["ecosystem", "package"]),
            models.Index(fields=["is_crypto", "relevance"]),
        ]
        constraints = [
            # One row per package per scope per manifest, so re-scanning the
            # same project updates rather than accumulating duplicates.
            models.UniqueConstraint(
                fields=["session", "package", "ecosystem", "scope", "location"],
                name="uniq_dependency_per_manifest",
            )
        ]

    def __str__(self) -> str:
        version = f" {self.version}" if self.version else ""
        return f"{self.package}{version} ({self.ecosystem})"


class DependencyRelation(models.Model):
    """A directed edge in the dependency graph.

    Two kinds of edge exist, and they answer different questions:

    * ``depends_on`` -- this package required that one. Read from a resolved
      lock file, so it is the real transitive shape rather than a guess.
    * ``provides``    -- this crypto package backs that discovered asset. Links
      a declared library to the algorithms actually observed using it.

    `AssetRelation` cannot carry these because both of its endpoints are
    CryptoAsset, and a Dependency is a different kind of node.
    """

    class RelationType(models.TextChoices):
        DEPENDS_ON = "depends_on", "Depends on"
        PROVIDES = "provides", "Provides"

    from_dependency = models.ForeignKey(
        Dependency,
        on_delete=models.CASCADE,
        related_name="outgoing_relations",
    )
    # Nullable: a `depends_on` edge has no asset endpoint. Exactly one of
    # to_dependency / to_asset is set, enforced below.
    to_dependency = models.ForeignKey(
        Dependency,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="incoming_relations",
    )
    to_asset = models.ForeignKey(
        CryptoAsset,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="dependency_relations",
    )
    relation_type = models.CharField(max_length=16, choices=RelationType.choices)
    detail = models.CharField(max_length=256, blank=True, default="")
    session = models.ForeignKey(
        "core.WorkSession",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="dependency_relations",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["id"]
        constraints = [
            models.CheckConstraint(
                check=(
                    models.Q(to_dependency__isnull=False, to_asset__isnull=True)
                    | models.Q(to_dependency__isnull=True, to_asset__isnull=False)
                ),
                name="dep_rel_exactly_one_target",
            ),
            models.UniqueConstraint(
                fields=["from_dependency", "to_dependency", "relation_type"],
                name="uniq_dep_rel_dependency",
            ),
            models.UniqueConstraint(
                fields=["from_dependency", "to_asset", "relation_type"],
                name="uniq_dep_rel_asset",
            ),
        ]

    def __str__(self) -> str:
        target = self.to_dependency or self.to_asset
        return f"{self.from_dependency} -{self.relation_type}-> {target}"


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
    session = models.ForeignKey(
        "core.WorkSession",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="asset_relations",
        help_text="Work session this relation belongs to (null = global).",
    )
    relation_type = models.CharField(max_length=16, choices=RelationType.choices)
    description = models.CharField(max_length=256, blank=True, default="")

    class Meta:
        unique_together = ("from_asset", "to_asset", "relation_type")

    def __str__(self) -> str:
        return f"{self.from_asset} {self.relation_type} {self.to_asset}"


class GraphNode(models.Model):
    """One typed node in the unified relationship graph.

    The domain models (CryptoAsset, Dependency, ScanJob) stay authoritative.
    A GraphNode is a *derived index* row that points back at whichever of them
    it came from, so the graph can join entities that previously lived in
    separate, unconnectable tables without copying their data.

    `key` is stable and content-addressed within a type, so rebuilding the
    index is idempotent and cross-references survive a rescan.
    """

    class NodeType(models.TextChoices):
        APPLICATION = "application", "Application"
        REPOSITORY = "repository", "Repository"
        CONTAINER = "container", "Container"
        FILE = "file", "File"
        API = "api", "API"
        LIBRARY = "library", "Library"
        DEPENDENCY = "dependency", "Dependency"
        ALGORITHM = "algorithm", "Algorithm"
        KEY = "key", "Key"
        CERTIFICATE = "certificate", "Certificate"
        PROTOCOL = "protocol", "Protocol"
        ENDPOINT = "endpoint", "Endpoint"
        INFRASTRUCTURE = "infrastructure", "Infrastructure"

    node_type = models.CharField(max_length=20, choices=NodeType.choices)
    key = models.CharField(
        max_length=512,
        help_text="Stable identity within the type, e.g. 'file:C:/app/x.py'.",
    )
    label = models.CharField(max_length=256, blank=True, default="")
    session = models.ForeignKey(
        "core.WorkSession",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="graph_nodes",
        help_text="Work session this node belongs to (null = global).",
    )
    # Link back to the authoritative row, when there is one. Deliberately not a
    # ForeignKey: one graph node can summarise a library that is both a
    # Dependency and a CryptoAsset.
    ref_model = models.CharField(max_length=32, blank=True, default="")
    ref_id = models.PositiveBigIntegerField(null=True, blank=True)
    # Denormalised for display and filtering without extra joins.
    family = models.CharField(max_length=16, blank=True, default="")
    algorithm = models.CharField(max_length=64, blank=True, default="")
    asset_type = models.CharField(max_length=32, blank=True, default="")
    source_type = models.CharField(max_length=16, blank=True, default="")
    location = models.CharField(max_length=1024, blank=True, default="")
    detail = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["node_type", "label", "key"]
        indexes = [
            models.Index(fields=["node_type"]),
            models.Index(fields=["session", "node_type"]),
            models.Index(fields=["key"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["session", "node_type", "key"],
                name="uniq_graph_node_per_session",
            )
        ]

    def __str__(self) -> str:
        return f"{self.node_type}:{self.label or self.key[:40]}"


class GraphEdge(models.Model):
    """A directed, typed relationship between two GraphNodes."""

    class RelationType(models.TextChoices):
        CONTAINS = "contains", "Contains"
        USES = "uses", "Uses"
        DEPENDS_ON = "depends_on", "Depends on"
        PROVIDES = "provides", "Provides"
        SIGNED_BY = "signed_by", "Signed by"
        EXPOSES = "exposes", "Exposes"
        IMPLEMENTS = "implements", "Implements"
        CO_LOCATED = "co_located", "Co-located"
        RELATES_TO = "relates_to", "Relates to"

    from_node = models.ForeignKey(
        GraphNode, on_delete=models.CASCADE, related_name="outgoing_edges"
    )
    to_node = models.ForeignKey(
        GraphNode, on_delete=models.CASCADE, related_name="incoming_edges"
    )
    relation_type = models.CharField(max_length=20, choices=RelationType.choices)
    session = models.ForeignKey(
        "core.WorkSession",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="graph_edges",
    )
    # Where this edge came from. An edge with no evidence is a guess, and this
    # builder only emits edges it can point at something.
    evidence = models.JSONField(default=dict, blank=True)
    confidence = models.FloatField(default=1.0)

    class Meta:
        indexes = [
            models.Index(fields=["relation_type"]),
            models.Index(fields=["from_node", "relation_type"]),
            models.Index(fields=["to_node", "relation_type"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["from_node", "to_node", "relation_type"],
                name="uniq_graph_edge",
            )
        ]

    def __str__(self) -> str:
        return f"{self.from_node} -{self.relation_type}-> {self.to_node}"
