"""URL routing for the discovery API."""

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .api import (
    AssetOccurrenceViewSet,
    AssetRelationViewSet,
    CryptoAssetViewSet,
    DependencyViewSet,
    NormalizedFindingViewSet,
    RawFindingViewSet,
    ScanJobViewSet,
    StatsViewSet,
)
from . import views

router = DefaultRouter()
router.register("scans", ScanJobViewSet, basename="scan")
router.register("raw-findings", RawFindingViewSet, basename="rawfinding")
router.register("normalized-findings", NormalizedFindingViewSet, basename="normalizedfinding")
router.register("assets", CryptoAssetViewSet, basename="cryptoasset")
router.register("occurrences", AssetOccurrenceViewSet, basename="assetoccurrence")
router.register("dependencies", DependencyViewSet, basename="dependency")
router.register("relations", AssetRelationViewSet, basename="assetrelation")
router.register("stats", StatsViewSet, basename="stats")

urlpatterns = [
    path("", include(router.urls)),
    path("scanners/", views.scanners, name="scanners"),
    path("run-demo-scan/", views.run_demo_scan, name="run-demo-scan"),
    path("start-scan/", views.start_scan, name="start-scan"),
    path("scans/<int:scan_id>/cancel/", views.cancel_scan, name="scan-cancel"),
    path("scans/<int:scan_id>/delete/", views.cancel_scan, name="scan-cancel-alt"),
    path("scan-batches/<int:batch_id>/", views.scan_batch, name="scan-batch"),
    path("scan-batches/<int:batch_id>/cancel/", views.cancel_scan_batch, name="scan-batch-cancel"),
    path("scan-data/", views.scan_data, name="scan-data"),
    path("graph/", views.graph_data, name="graph-data"),
    path("graph/correlate/", views.graph_correlate, name="graph-correlate"),
    path("graph-index/", views.graph_index, name="graph-index"),
    path("graph-index/<int:node_id>/impact/", views.graph_impact, name="graph-impact"),
    path("handoff/", views.handoff, name="handoff"),
    path("browse/", views.browse, name="browse"),
    path("scan-preview/", views.scan_preview, name="scan-preview"),
]
