"""URL configuration for the ECDAT backend API service."""

from django.contrib import admin
from django.urls import include, path

from core import views as core_views

urlpatterns = [
    path('admin/', admin.site.urls),
    # Service root + health
    path('api/health/', core_views.health, name="health"),
    # ECDAT workstream API — one mount per segment (paths are stable and
    # documented in docs/api/).
    path('api/', include('segments.scraping.discovery.urls')),
    path('api/analysis/', include('segments.ml.analysis.urls')),
    path('api/session/', include('core.urls')),
    path('api/mitigation/', include('segments.mitigation.mitigation.urls')),
    path('api/crypto/', include('segments.scraping.crypto_scan.urls')),
    path('api/reports/', include('segments.reporting.reports.urls')),
    path('api/reporting/', include('segments.reporting.dashboard.urls')),
]