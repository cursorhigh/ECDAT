from django.contrib import admin

from .models import MitigationPlan


@admin.register(MitigationPlan)
class MitigationPlanAdmin(admin.ModelAdmin):
    list_display = ("id", "run", "status", "progress", "generated_at", "created_at")
    list_filter = ("status", "mode")
    search_fields = ("run__id",)