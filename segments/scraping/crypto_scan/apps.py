from django.apps import AppConfig


class CryptoScanConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "segments.scraping.crypto_scan"
    verbose_name = "Crypto Scan Pipeline"
