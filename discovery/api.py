"""DRF views / API endpoints for the discovery app.

Provides JSON data for the dashboard widgets (ECharts + HTMX tables).
"""

from django.db.models import Count
from rest_framework import filters, viewsets

from core.models import AuditLog
from .models import (
    AssetRelation,
    CryptoAsset,
    NormalizedFinding,
    RawFinding,
    ScanJob,
)
from .serializers import (
    AssetRelationSerializer,
    CryptoAssetSerializer,
    NormalizedFindingSerializer,
    RawFindingSerializer,
    ScanJobSerializer,
)


class ScanJobViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ScanJob.objects.all().order_by("-created_at")
    serializer_class = ScanJobSerializer
    filter_backends = [filters.OrderingFilter]
    ordering_fields = ["created_at", "status", "source_type"]


class RawFindingViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = RawFinding.objects.all().select_related("scan_job").order_by("-ingested_at")
    serializer_class = RawFindingSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["location"]
    ordering_fields = ["ingested_at"]


class NormalizedFindingViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = NormalizedFinding.objects.all().select_related("raw_finding").order_by("family")
    serializer_class = NormalizedFindingSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["algorithm", "library", "protocol"]
    ordering_fields = ["algorithm", "key_size"]


class CryptoAssetViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = CryptoAsset.objects.all().order_by("name")
    serializer_class = CryptoAssetSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["name", "algorithm", "location", "owner"]
    ordering_fields = ["name", "family", "key_size"]


class AssetRelationViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = AssetRelation.objects.all().select_related("from_asset", "to_asset").order_by("id")
    serializer_class = AssetRelationSerializer


class StatsViewSet(viewsets.ViewSet):
    """Aggregate stats for dashboard widgets."""

    def list(self, request):
        scans = ScanJob.objects.all()
        raw = RawFinding.objects.all()
        normalized = NormalizedFinding.objects.all()
        assets = CryptoAsset.objects.all()
        relations = AssetRelation.objects.all()

        return self._build(
            {
                "scan_total": scans.count(),
                "scan_completed": scans.filter(status=ScanJob.Status.COMPLETED).count(),
                "scan_running": scans.filter(status=ScanJob.Status.RUNNING).count(),
                "scan_failed": scans.filter(status=ScanJob.Status.FAILED).count(),
                "raw_total": raw.count(),
                "raw_by_source": self._group(raw, "source_type"),
                "raw_by_status": self._group(raw, "status"),
                "normalized_total": normalized.count(),
                "normalized_unknown": normalized.filter(family=NormalizedFinding.AlgorithmFamily.UNKNOWN).count(),
                "asset_total": assets.count(),
                "asset_by_family": self._group(assets, "family"),
                "asset_by_source": self._group(assets, "source_type"),
                "asset_by_owner": self._group(assets, "owner"),
                "asset_by_status": self._group(assets, "inventory_status"),
                "relation_total": relations.count(),
                "relation_by_type": self._group(relations, "relation_type"),
                "audit_total": AuditLog.objects.count(),
            }
        )

    @staticmethod
    def _group(qs, field):
        return list(qs.values(field).annotate(count=Count("id")).order_by("-count"))

    @staticmethod
    def _build(data):
        from rest_framework.response import Response

        return Response(data)
