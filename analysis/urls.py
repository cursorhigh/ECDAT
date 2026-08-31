"""URL routing for the analysis API."""

from django.urls import path

from . import views

urlpatterns = [
    path("", views.analysis_list, name="analysis-list"),
    path("awaiting/", views.analysis_awaiting, name="analysis-awaiting"),
    path("start/", views.analysis_start, name="analysis-start"),
    path("<int:run_id>/", views.analysis_detail, name="analysis-detail"),
    path("<int:run_id>/artifacts/", views.analysis_artifacts, name="analysis-artifacts"),
]