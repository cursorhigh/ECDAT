"""URL routing for the analysis API."""

from django.urls import path

from . import views

urlpatterns = [
    path("", views.analysis_list, name="analysis-list"),
    path("awaiting/", views.analysis_awaiting, name="analysis-awaiting"),
    path("start/", views.analysis_start, name="analysis-start"),
    path("<int:run_id>/", views.analysis_detail, name="analysis-detail"),
    path("<int:run_id>/cancel/", views.analysis_cancel, name="analysis-cancel"),
    path("<int:run_id>/pause/", views.analysis_pause, name="analysis-pause"),
    path("<int:run_id>/resume/", views.analysis_resume, name="analysis-resume"),
    path("<int:run_id>/artifacts/", views.analysis_artifacts, name="analysis-artifacts"),
    # Whole-scope export first: "cbom/" must not be swallowed by "<int:run_id>/".
    path("cbom/", views.cbom_export, name="cbom-export"),
    path("<int:run_id>/cbom/", views.cbom_export, name="analysis-cbom"),
]