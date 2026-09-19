"""Reusable dashboard template filters."""

from django import template
from django.utils.safestring import mark_safe

register = template.Library()

# Discovery category (ScanJob.SourceType) -> badge color.
_CATEGORY_COLORS = {
    "source_code": "green",
    "binary": "amber",
    "dependency": "indigo",
    "container": "gray",
    "certificate": "red",
    "hsm": "amber",
    "cloud": "indigo",
}

# Blast severity / overall risk -> badge color.
_SEVERITY_BADGES = {
    "CRITICAL": "badge-red",
    "HIGH": "badge-red",
    "MEDIUM": "badge-amber",
    "LOW": "badge-green",
}


@register.filter
def sev_badge(value):
    """Map a severity/risk label to a badge class (defaults to amber)."""
    return _SEVERITY_BADGES.get(str(value or "").upper(), "badge-amber")


@register.filter
def category_badge(obj):
    """Render a colored category chip for a discovery model instance.

    Accepts any model exposing ``source_type`` + ``get_source_type_display()``
    (CryptoAsset / NormalizedFinding / RawFinding).
    """
    key = getattr(obj, "source_type", "") or ""
    label = (getattr(obj, "get_source_type_display", lambda: key)() or key).title()
    color = _CATEGORY_COLORS.get(key, "gray")
    return mark_safe(f'<span class="badge badge-{color}">{label}</span>')