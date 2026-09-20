from django.contrib import admin

from .models import AnalysisRun, AssetAssessment


@admin.register(AnalysisRun)
class AnalysisRunAdmin(admin.ModelAdmin):
    list_display = ("id", "scan_job", "status", "progress", "mode", "created_at")
    list_filter = ("status", "mode")


@admin.register(AssetAssessment)
class AssetAssessmentAdmin(admin.ModelAdmin):
    list_display = ("id", "run", "finding_ref", "asset", "mode")
    list_filter = ("mode",)
