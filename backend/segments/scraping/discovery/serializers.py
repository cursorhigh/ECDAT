"""DRF serializers for the discovery app."""

from rest_framework import serializers

from .models import AssetRelation, CryptoAsset, NormalizedFinding, RawFinding, ScanJob


class ScanJobSerializer(serializers.ModelSerializer):
    source_type_display = serializers.CharField(source="get_source_type_display", read_only=True)
    status_display = serializers.CharField(source="get_status_display", read_only=True)

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
            "findings_count",
            "error",
            "started_at",
            "finished_at",
            "created_at",
        ]


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

    class Meta:
        model = NormalizedFinding
        fields = [
            "id",
            "raw_finding",
            "family",
            "family_display",
            "algorithm",
            "key_size",
            "curve",
            "protocol",
            "library",
            "library_version",
            "confidence",
        ]


class CryptoAssetSerializer(serializers.ModelSerializer):
    family_display = serializers.CharField(source="get_family_display", read_only=True)
    inventory_status_display = serializers.CharField(source="get_inventory_status_display", read_only=True)

    class Meta:
        model = CryptoAsset
        fields = [
            "id",
            "name",
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
            "created_at",
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
