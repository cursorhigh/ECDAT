"""URL routing for the core app (work-session endpoints)."""

from django.urls import path

from . import views

urlpatterns = [
    path("info/", views.session_info, name="session-info"),
    path("create/", views.session_create, name="session-create"),
    path("switch/<int:session_id>/", views.session_switch, name="session-switch"),
    path("reset/", views.session_reset, name="session-reset"),
    path("audit/", views.audit, name="session-audit"),
    path("scan-history/", views.scan_history, name="scan-history"),
    path("scan-history/clear/", views.clear_all_scan_history, name="scan-history-clear"),
    path("scan-history/<int:session_id>/delete/", views.delete_scan_history_session, name="scan-history-delete"),
    path("scans/<int:scan_id>/delete/", views.delete_scan_job, name="scan-job-delete"),
]