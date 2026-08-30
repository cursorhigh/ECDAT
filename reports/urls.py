"""URL routing for the reports app."""

from django.urls import path

from . import views

urlpatterns = [
    path("assets.csv", views.export_assets_csv, name="export-assets-csv"),
    path("assets.json", views.export_assets_json, name="export-assets-json"),
    path("raw.csv", views.export_raw_csv, name="export-raw-csv"),
    path("normalized.csv", views.export_normalized_csv, name="export-normalized-csv"),
]
