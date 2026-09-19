"""URL configuration for config project."""

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path('admin/', admin.site.urls),
    # ECDAT apps
    path('', include('segments.reporting.dashboard.urls')),
    path('api/', include('segments.scraping.discovery.urls')),
    path('api/analysis/', include('segments.ml.analysis.urls')),
    path('api/session/', include('core.urls')),
    path('api/mitigation/', include('segments.mitigation.mitigation.urls')),
    path('reports/', include('segments.reporting.reports.urls')),
    path('crypto/', include('segments.scraping.crypto_scan.urls')),
]
