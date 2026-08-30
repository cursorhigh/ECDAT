"""URL configuration for config project."""

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path('admin/', admin.site.urls),
    # ECDAT apps
    path('', include('dashboard.urls')),
    path('api/', include('discovery.urls')),
    path('reports/', include('reports.urls')),
]
