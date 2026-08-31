"""URL configuration for config project."""

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path('admin/', admin.site.urls),
    # ECDAT apps
    path('', include('dashboard.urls')),
    path('api/', include('discovery.urls')),
    path('api/analysis/', include('analysis.urls')),
    path('api/session/', include('core.urls')),
    path('api/mitigation/', include('mitigation.urls')),
    path('reports/', include('reports.urls')),
    path('crypto/', include('crypto_scan.urls')),
]
