from django.contrib import admin
from .models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("created_at", "action", "actor", "target_type", "target_id")
    list_filter = ("action", "created_at")
    search_fields = ("message", "target_type", "target_id")
    readonly_fields = (
        "action",
        "actor",
        "target_type",
        "target_id",
        "message",
        "created_at",
    )
