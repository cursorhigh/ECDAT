from django.contrib import admin
from .models import ApiKey, AuditLog


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


@admin.register(ApiKey)
class ApiKeyAdmin(admin.ModelAdmin):
    list_display = ("name", "prefix", "is_active", "last_used_at", "created_at")
    list_filter = ("is_active", "created_at")
    search_fields = ("name", "prefix")
    readonly_fields = ("prefix", "hashed_key", "last_used_at", "created_at")
