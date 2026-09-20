"""URL routing for the mitigation API."""

from django.urls import path

from . import views

urlpatterns = [
    path("", views.plan_list, name="mitigation-list"),
    path("overview/", views.plan_overview, name="mitigation-overview"),
    path("<int:plan_id>/", views.plan_detail, name="mitigation-detail"),
    path("<int:plan_id>/cancel/", views.plan_cancel, name="mitigation-cancel"),
    path("run/<int:run_id>/generate/", views.plan_generate, name="mitigation-generate"),
]