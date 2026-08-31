"""URL routing for the core app (work-session endpoints)."""

from django.urls import path

from . import views

urlpatterns = [
    path("info/", views.session_info, name="session-info"),
    path("create/", views.session_create, name="session-create"),
    path("switch/<int:session_id>/", views.session_switch, name="session-switch"),
    path("reset/", views.session_reset, name="session-reset"),
]