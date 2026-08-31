"""DRF views / API endpoints for the discovery app.

Provides JSON data for the dashboard widgets (ECharts + HTMX tables).
"""

from django.db.models import Count
from rest_framework import filters, viewsets

from core.models import AuditLog
from core.sessions import scope, thread_session_id
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
    serializer_class = ScanJobSerializer
    filter_backends = [filters.OrderingFilter]
    ordering_fields = ["created_at", "status", "source_type"]

    def get_queryset(self):
        return scope(ScanJob.objects.all(), thread_session_id()).order_by("-created_at")


class RawFindingViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = RawFindingSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["location"]
    ordering_fields = ["ingested_at"]

    def get_queryset(self):
        return (
            scope(RawFinding.objects.all(), thread_session_id())
            .select_related("scan_job")
            .order_by("-ingested_at")
        )


class NormalizedFindingViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = NormalizedFindingSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["algorithm", "library", "protocol"]
    ordering_fields = ["algorithm", "key_size"]

    def get_queryset(self):
        return (
            scope(NormalizedFinding.objects.all(), thread_session_id())
            .select_related("raw_finding")
            .order_by("family")
        )


class CryptoAssetViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = CryptoAssetSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["name", "algorithm", "location", "owner"]
    ordering_fields = ["name", "family", "key_size"]

    def get_queryset(self):
        return scope(CryptoAsset.objects.all(), thread_session_id()).order_by("name")


class AssetRelationViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = AssetRelationSerializer

    def get_queryset(self):
        return (
            scope(AssetRelation.objects.all(), thread_session_id())
            .select_related("from_asset", "to_asset")
            .order_by("id")
        )


class StatsViewSet(viewsets.ViewSet):
    """Aggregate stats for dashboard widgets."""

    def list(self, request):
        sid = thread_session_id()
        scans = scope(ScanJob.objects.all(), sid)
        raw = scope(RawFinding.objects.all(), sid)
        normalized = scope(NormalizedFinding.objects.all(), sid)
        assets = scope(CryptoAsset.objects.all(), sid)
        relations = scope(AssetRelation.objects.all(), sid)
        audit = scope(AuditLog.objects.all(), sid)

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
                "audit_total": audit.count(),
            }
        )

    @staticmethod
    def _group(qs, field):
        return list(qs.values(field).annotate(count=Count("id")).order_by("-count"))

    @staticmethod
    def _build(data):
        from rest_framework.response import Response

        return Response(data)
