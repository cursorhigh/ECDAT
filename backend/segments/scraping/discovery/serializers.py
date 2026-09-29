"""DRF serializers for the discovery app."""

from rest_framework import serializers

from .models import (
    AssetOccurrence,
    AssetRelation,
    CryptoAsset,
    Dependency,
    NormalizedFinding,
    RawFinding,
    ScanBatch,
    ScanJob,
)


class ScanJobSerializer(serializers.ModelSerializer):
    source_type_display = serializers.CharField(source="get_source_type_display", read_only=True)
    status_display = serializers.CharField(source="get_status_display", read_only=True)
    skip_reason_labels = serializers.SerializerMethodField()

    class Meta:
        model = ScanJob
        fields = [
            "id",
            "source_type",
            "source_type_display",
            "target",
            "status",
            "status_display",
            "progress",
            "progress_stage",
            "items_total",
            "items_scanned",
            "items_skipped",
            "skip_reasons",
            "skip_reason_labels",
            "findings_count",
            # A multi-source run creates one ScanJob per source inside a single
            # session, so the job list alone reads as several unrelated scans.
            # Exposing the batch lets the client collapse them back into the one
            # user action that produced them.
            "batch",
            "error",
            "error_code",
            "error_scope",
            "error_recoverable",
            "error_action",
            "started_at",
            "finished_at",
            "created_at",
        ]

    def get_skip_reason_labels(self, obj) -> list[dict]:
        """Each skip reason with a readable label, for display not diagnosis."""
        from .services import _SKIP_LABELS

        reasons = obj.skip_reasons or {}
        return [
            {
                "reason": reason,
                "count": count,
                "label": _SKIP_LABELS.get(reason, "items could not be inspected"),
            }
            for reason, count in sorted(
                reasons.items(), key=lambda kv: (-kv[1], kv[0])
            )
        ]


class ScanBatchSerializer(serializers.ModelSerializer):
    """One user action across several sources, with per-source detail.

    The batch reports what actually ran, including anything that was left out
    and why, so a "scan everything" request never quietly scans less than asked.
    """

    status_display = serializers.CharField(source="get_status_display", read_only=True)
    sources = serializers.SerializerMethodField()
    findings_count = serializers.SerializerMethodField()

    class Meta:
        model = ScanBatch
        fields = [
            "id",
            "target",
            "scan_type",
            "source_types",
            "excluded",
            "sources",
            "status",
            "status_display",
            "progress",
            "findings_count",
            "created_at",
            "finished_at",
        ]

    def get_sources(self, obj) -> list[dict]:
        return [
            {
                "id": job.pk,
                "source_type": job.source_type,
                "status": job.status,
                "progress": job.progress,
                "items_total": job.items_total,
                "items_scanned": job.items_scanned,
                "items_skipped": job.items_skipped,
                "findings_count": job.findings_count,
                "error": job.error,
                "error_code": job.error_code,
                "error_action": job.error_action,
                "skip_reasons": job.skip_reasons,
                "skip_reason_labels": ScanJobSerializer().get_skip_reason_labels(job),
            }
            for job in obj.jobs.order_by("id")
        ]

    def get_findings_count(self, obj) -> int:
        return sum(job.findings_count for job in obj.jobs.all())


class RawFindingSerializer(serializers.ModelSerializer):
    source_type_display = serializers.CharField(source="get_source_type_display", read_only=True)
    status_display = serializers.CharField(source="get_status_display", read_only=True)

    class Meta:
        model = RawFinding
        fields = [
            "id",
            "scan_job",
            "source_type",
            "source_type_display",
            "location",
            "raw_json",
            "status",
            "status_display",
            "ingested_at",
        ]


class NormalizedFindingSerializer(serializers.ModelSerializer):
    family_display = serializers.CharField(source="get_family_display", read_only=True)
    kind_display = serializers.CharField(source="get_kind_display", read_only=True)

    class Meta:
        model = NormalizedFinding
        fields = [
            "id",
            "raw_finding",
            "kind",
            "kind_display",
            "family",
            "family_display",
            "algorithm",
            "key_size",
            "curve",
            "protocol",
            "library",
            "library_version",
            "confidence",
            "line",
            "evidence",
        ]


class CryptoAssetSerializer(serializers.ModelSerializer):
    family_display = serializers.CharField(source="get_family_display", read_only=True)
    inventory_status_display = serializers.CharField(source="get_inventory_status_display", read_only=True)
    asset_type_display = serializers.CharField(source="get_asset_type_display", read_only=True)
    occurrence_count = serializers.IntegerField(read_only=True, default=0)

    class Meta:
        model = CryptoAsset
        fields = [
            "id",
            "name",
            "asset_type",
            "asset_type_display",
            "identifier",
            "environment",
            "family",
            "family_display",
            "algorithm",
            "key_size",
            "curve",
            "protocol",
            "library",
            "library_version",
            "source_type",
            "location",
            "owner",
            "inventory_status",
            "inventory_status_display",
            "occurrence_count",
            "created_at",
        ]


class AssetOccurrenceSerializer(serializers.ModelSerializer):
    asset_name = serializers.CharField(source="asset.name", read_only=True)
    asset_type = serializers.CharField(source="asset.asset_type", read_only=True)

    class Meta:
        model = AssetOccurrence
        fields = [
            "id",
            "asset",
            "asset_name",
            "asset_type",
            "scan_job",
            "finding",
            "location",
            "line",
            "first_seen",
            "last_seen",
            "evidence",
        ]


class DependencySerializer(serializers.ModelSerializer):
    class Meta:
        model = Dependency
        fields = [
            "id",
            "package",
            "version",
            "ecosystem",
            "scope",
            "is_crypto",
            "relevance",
            "capability",
            "key_service",
            "family",
            "location",
            "source_path",
            "evidence",
        ]


class AssetRelationSerializer(serializers.ModelSerializer):
    relation_type_display = serializers.CharField(source="get_relation_type_display", read_only=True)
    from_asset_name = serializers.CharField(source="from_asset.name", read_only=True)
    to_asset_name = serializers.CharField(source="to_asset.name", read_only=True)

    class Meta:
        model = AssetRelation
        fields = [
            "id",
            "from_asset",
            "from_asset_name",
            "to_asset",
            "to_asset_name",
            "relation_type",
            "relation_type_display",
            "description",
        ]
