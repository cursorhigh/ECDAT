from django.contrib import admin

from .models import AssetRelation, CryptoAsset, NormalizedFinding, RawFinding, ScanJob


@admin.register(ScanJob)
class ScanJobAdmin(admin.ModelAdmin):
    list_display = ("id", "source_type", "target", "status", "progress", "findings_count", "created_at")
    list_filter = ("source_type", "status", "created_at")
    search_fields = ("target",)


@admin.register(RawFinding)
class RawFindingAdmin(admin.ModelAdmin):
    list_display = ("id", "source_type", "location", "status", "ingested_at")
    list_filter = ("source_type", "status", "ingested_at")
    search_fields = ("location",)


@admin.register(NormalizedFinding)
class NormalizedFindingAdmin(admin.ModelAdmin):
    list_display = ("id", "family", "algorithm", "key_size", "curve", "protocol", "confidence")
    list_filter = ("family", "protocol")
    search_fields = ("algorithm", "library")


@admin.register(CryptoAsset)
class CryptoAssetAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "family", "algorithm", "key_size", "source_type", "owner", "inventory_status")
    list_filter = ("family", "source_type", "inventory_status")
    search_fields = ("name", "algorithm", "location", "owner")


@admin.register(AssetRelation)
class AssetRelationAdmin(admin.ModelAdmin):
    list_display = ("id", "from_asset", "to_asset", "relation_type")
    list_filter = ("relation_type",)
