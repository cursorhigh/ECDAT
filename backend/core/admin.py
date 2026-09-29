from django.contrib import admin
from .models import ApiKey, AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    """Read-only window onto the audit trail.

    ``readonly_fields`` alone is not enough: the change form still offers a
    Save, and the changelist still offers the ``delete_selected`` action. Every
    write path has to be closed, so add/change/delete are all denied and the
    delete action is removed.
    """

    list_display = ("created_at", "action", "session_name", "actor", "target_type", "target_id")
    list_filter = ("action", "created_at")
    search_fields = ("message", "target_type", "target_id", "session_name")
    readonly_fields = (
        "action",
        "session",
        "session_name",
        "actor",
        "target_type",
        "target_id",
        "message",
        "created_at",
    )

    def has_add_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def get_actions(self, request):
        """Drop ``delete_selected`` -- otherwise the changelist bulk-deletes."""
        actions = super().get_actions(request)
        actions.pop("delete_selected", None)
        return actions


@admin.register(ApiKey)
class ApiKeyAdmin(admin.ModelAdmin):
    list_display = ("name", "prefix", "is_active", "last_used_at", "created_at")
    list_filter = ("is_active", "created_at")
    search_fields = ("name", "prefix")
    readonly_fields = ("prefix", "hashed_key", "last_used_at", "created_at")
