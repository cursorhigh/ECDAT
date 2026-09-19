"""URL routing for the dashboard pages."""

from django.urls import path

from . import views

urlpatterns = [
    path("", views.overview, name="dashboard-overview"),
    path("discovery/", views.discovery, name="dashboard-discovery"),
    path("inventory/", views.inventory, name="dashboard-inventory"),
    path("graph/", views.asset_graph, name="dashboard-graph"),
    path("audit/", views.audit_log, name="dashboard-audit"),
    path("analysis/", views.analysis, name="dashboard-analysis"),
    path("analysis/<int:run_id>/", views.analysis_detail, name="dashboard-analysis-detail"),
    path("mitigation/", views.mitigation, name="dashboard-mitigation"),
    path("mitigation/<int:plan_id>/", views.mitigation_detail, name="dashboard-mitigation-detail"),
    path("reports/", views.reports, name="dashboard-reports"),
]
