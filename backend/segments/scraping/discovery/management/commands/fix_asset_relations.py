"""Backfill asset-relation session scoping.

Before the correlation engine attached edges to the asset's work session,
every AssetRelation row was created with ``session=NULL`` -- so under an
active work session the graph scoped them out and showed no correlation
links at all. This command stamps each legacy global edge with the session
of its endpoints (edges between two same-session assets go to that session,
a mixed edge keeps the non-global session, otherwise stays global).

Usage:
    python manage.py fix_asset_relations
"""

import json

from django.core.management.base import BaseCommand

from segments.scraping.discovery.models import AssetRelation


class Command(BaseCommand):
    help = "Stamps legacy session=NULL AssetRelation edges with their assets' session."

    def add_arguments(self, parser):
        parser.add_argument("--db", default="default", help="Database alias (default: default).")

    def handle(self, *args, **options):
        db = options["db"]
        fixed = 0
        qs = (
            AssetRelation.objects.using(db)
            .filter(session__isnull=True)
            .select_related("from_asset", "to_asset")
        )
        for obj in qs.iterator():
            sids = {obj.from_asset.session_id, obj.to_asset.session_id}
            own = next((s for s in sids if s is not None), None)
            if own is None:
                continue
            obj.session_id = own
            obj.save(using=db, update_fields=["session_id"])
            fixed += 1
        self.stdout.write(self.style.SUCCESS(f"[{db}] stamped {fixed} relations with a session."))