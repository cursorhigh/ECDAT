"""Correlation Engine (Segment A).

Builds AssetRelation edges in the Crypto Asset Graph:
- Assets sharing the same location/repo are 'context' related.
- Assets sharing the same algorithm family are 'relate' related.
- Optional: asset A 'contains' algorithm B when A is a composite (future).
"""

from .models import AssetRelation, CryptoAsset


def build_correlations(assets=None, using=None) -> int:
    """(Re)build graph edges for the given assets (or all assets).

    `using` selects the database (defaults to the calling code; if assets are
    passed they are used as the queryset source). All edges are written inside
    the same database so they stay within the active mode boundary.
    """
    db = using or "default"
    qs = assets if assets is not None else CryptoAsset.objects.using(db).all()
    created = 0

    assets_list = list(qs.select_related().all())

    # relate: same family
    by_family: dict[str, list[CryptoAsset]] = {}
    for a in assets_list:
        by_family.setdefault(a.family, []).append(a)
    for family, group in by_family.items():
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                a, b = group[i], group[j]
                if a.pk == b.pk:
                    continue
                obj, was = AssetRelation.objects.using(db).get_or_create(
                    from_asset=a,
                    to_asset=b,
                    relation_type=AssetRelation.RelationType.RELATE,
                    defaults={"mode": a.mode, "description": f"Shared algorithm family {family}"},
                )
                if was:
                    created += 1

    # context: same location repo prefix
    by_repo: dict[str, list[CryptoAsset]] = {}
    for a in assets_list:
        if not a.location:
            continue  # Skip assets with no location — they share no context.
        repo = (a.location or "").split("/src")[0] or a.location
        by_repo.setdefault(repo, []).append(a)
    for _repo, group in by_repo.items():
        if len(group) < 2:
            continue
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                a, b = group[i], group[j]
                if a.pk == b.pk:
                    continue
                obj, was = AssetRelation.objects.using(db).get_or_create(
                    from_asset=a,
                    to_asset=b,
                    relation_type=AssetRelation.RelationType.CONTEXT,
                    defaults={"mode": a.mode, "description": "Share a deployment/context"},
                )
                if was:
                    created += 1

    return created
