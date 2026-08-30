"""URL routing for the discovery API."""

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .api import (
    AssetRelationViewSet,
    CryptoAssetViewSet,
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
router.register("relations", AssetRelationViewSet, basename="assetrelation")
router.register("stats", StatsViewSet, basename="stats")

urlpatterns = [
    path("", include(router.urls)),
    path("run-demo-scan/", views.run_demo_scan, name="run-demo-scan"),
    path("start-scan/", views.start_scan, name="start-scan"),
    path("scan-data/", views.scan_data, name="scan-data"),
    path("browse/", views.browse, name="browse"),

]
