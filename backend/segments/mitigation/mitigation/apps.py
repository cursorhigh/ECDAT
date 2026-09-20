from django.apps import AppConfig


class MitigationConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "segments.mitigation.mitigation"
    verbose_name = "Mitigation Planning"