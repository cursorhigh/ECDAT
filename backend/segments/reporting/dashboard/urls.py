"""URL routing for the reporting/estate-metrics API."""

from django.urls import path

from . import views

urlpatterns = [
    path("overview/", views.overview, name="dashboard-api-overview"),
    path("pipeline/", views.pipeline, name="dashboard-api-pipeline"),
    path("audit/", views.audit, name="dashboard-api-audit"),
]