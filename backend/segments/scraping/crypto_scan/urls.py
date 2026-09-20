"""URL routing for the crypto-scan pipeline."""

from django.urls import path

from . import views

urlpatterns = [
    path("scan/start/", views.start_scan, name="crypto-scan-start"),
    path("scan/<int:scan_id>/status/", views.scan_status, name="crypto-scan-status"),
    path("scan/<int:scan_id>/cancel/", views.cancel_scan, name="crypto-scan-cancel"),
]
