"""DRF views / API endpoints for the discovery app.

Provides JSON data for the dashboard widgets (ECharts + HTMX tables).
"""

from django.db.models import Count
from rest_framework import filters, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from core.models import AuditLog
from core.sessions import scope, thread_session_id
from .models import (
    AssetOccurrence,
    AssetRelation,
    CryptoAsset,
    Dependency,
    DependencyRelation,
    NormalizedFinding,
    RawFinding,
    ScanJob,
)
from .serializers import (
    AssetOccurrenceSerializer,
    AssetRelationSerializer,
    CryptoAssetSerializer,
    DependencySerializer,
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
    ordering_fields = ["algorithm", "key_size", "confidence", "kind", "family"]

    # Filters applied explicitly rather than via a filter backend, so the
    # project keeps its existing dependency set. An unrecognised value is
    # ignored rather than silently returning an empty page.
    FILTERS = ("kind", "family", "algorithm", "source_type", "scan_job")

    def get_queryset(self):
        qs = (
            scope(NormalizedFinding.objects.all(), thread_session_id())
            .select_related("raw_finding")
            .order_by("family")
        )
        params = self.request.query_params
        for field in self.FILTERS:
            value = params.get(field)
            if value:
                qs = qs.filter(**{field: value})
        return qs

    @action(detail=False, methods=["get"], url_path="kinds")
    def kinds(self, request):
        """Counts per artefact kind, so the UI can offer real classification.

        Discovery distinguishes certificates, keys, protocols, libraries and
        dependencies rather than one flat list of algorithms. A user needs to
        see that split, not infer it from row text.
        """
        from .normalizer import canonical_kind_counts

        counts = canonical_kind_counts(
            scope(NormalizedFinding.objects.all(), thread_session_id())
        )
        labels = dict(NormalizedFinding.FindingKind.choices)
        return Response(
            {
                "total": sum(counts.values()),
                "kinds": [
                    {
                        "kind": kind,
                        "label": labels.get(kind, "Unknown artefact"),
                        "count": count,
                    }
                    # Most present first; ties by label so the order is stable.
                    for kind, count in sorted(
                        counts.items(), key=lambda kv: (-kv[1], labels.get(kv[0], kv[0]))
                    )
                ],
            }
        )


class CryptoAssetViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = CryptoAssetSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["name", "algorithm", "location", "owner"]
    ordering_fields = ["name", "family", "key_size"]

    def get_queryset(self):
        qs = (
            scope(CryptoAsset.objects.all(), thread_session_id())
            .annotate(occurrence_count=Count("occurrences", distinct=True))
            .order_by("name")
        )
        requested = self.request.query_params.get("asset_type")
        if requested:
            qs = qs.filter(asset_type=requested)
        return qs


class AssetOccurrenceViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = AssetOccurrenceSerializer
    filter_backends = [filters.OrderingFilter]
    ordering_fields = ["last_seen", "location"]

    def get_queryset(self):
        # An occurrence has no session of its own; it belongs to its asset, so
        # scope through the asset rather than adding a redundant column.
        session_id = thread_session_id()
        if not session_id:
            return AssetOccurrence.objects.none()
        queryset = (
            AssetOccurrence.objects.all()
            .filter(asset__session_id=session_id)
            .select_related("asset")
        )
        requested_asset = self.request.query_params.get("asset")
        if requested_asset and requested_asset.isdigit():
            queryset = queryset.filter(asset_id=int(requested_asset))
        return queryset.order_by("-last_seen")


class DependencyViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = DependencySerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["package", "capability", "ecosystem"]
    ordering_fields = ["package", "ecosystem", "relevance"]

    def get_queryset(self):
        # No `.using(...)` here: the router resolves the active mode's database,
        # matching every other viewset in this module.
        qs = scope(Dependency.objects.all(), thread_session_id())
        if self.request.query_params.get("crypto_only") in ("1", "true", "True"):
            qs = qs.filter(is_crypto=True)
        return qs.order_by("package")


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
        dep_relations = scope(DependencyRelation.objects.all(), sid)
        dependencies = scope(Dependency.objects.all(), sid)
        audit = scope(AuditLog.objects.all(), sid)

        return self._build(
            {
                "scan_total": scans.count(),
                "scan_completed": scans.filter(status=ScanJob.Status.COMPLETED).count(),
                "scan_partial": scans.filter(status=ScanJob.Status.PARTIAL).count(),
                "scan_cancelled": scans.filter(status=ScanJob.Status.CANCELLED).count(),
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
                "dependency_total": dependencies.count(),
                "dependency_edge_total": dep_relations.count(),
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
