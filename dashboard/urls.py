"""URL routing for the dashboard pages."""

from django.urls import path

from . import views

urlpatterns = [
    path("", views.overview, name="dashboard-overview"),
    path("discovery/", views.discovery, name="dashboard-discovery"),
    path("inventory/", views.inventory, name="dashboard-inventory"),
    path("graph/", views.asset_graph, name="dashboard-graph"),
    path("audit/", views.audit_log, name="dashboard-audit"),
    path("risk/", views.placeholder, {"key": "risk"}, name="dashboard-risk"),
    path("mitigation/", views.placeholder, {"key": "mitigation"}, name="dashboard-mitigation"),
    path("reports/", views.placeholder, {"key": "reports"}, name="dashboard-reports"),
]
