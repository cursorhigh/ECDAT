"""Correlation Engine (Segment A).

Builds AssetRelation edges in the Crypto Asset Graph:
- Assets sharing the same location/repo are 'context' related.
- Assets sharing the same algorithm family are 'relate' related.
- Optional: asset A 'contains' algorithm B when A is a composite (future).
"""

from .models import AssetRelation, CryptoAsset

try:
    import posixpath
except ImportError:  # pragma: no cover
    import posixpath


def _context_repo(location: str) -> str:
    """The deployment/context bucket an asset belongs to.

    Locations may come from any OS (``C:\\...``, ``/src/...``); normalise to
    POSIX separators and bucket by the parent folder so assets scanned from
    the same repo/directory correlate on a shared context.
    """
    loc = (location or "").replace("\\", "/").strip().rstrip("/")
    if not loc:
        return ""
    return posixpath.dirname(loc) or loc


def build_correlations(assets=None, using=None) -> int:
    """(Re)build graph edges for the given assets (or all assets).

    `using` selects the database (defaults to the calling code; if assets are
    passed they are used as the queryset source). All edges are written inside
    the same database so they stay within the active mode boundary.

    Edges are scoped to ``session_id`` whenever every asset in the pair belongs
    to that session (an asset with no session is treated as belonging to all
    sessions). This keeps graph edges visible under a work session instead of
    silently attaching to the global (NULL) bucket.
    """
    db = using or "default"
    targets = assets if assets is not None else CryptoAsset.objects.using(db).all()
    created = 0

    assets_list = list(targets.select_related().all())

    def edge_session(a: "CryptoAsset", b: "CryptoAsset"):
        """A new edge's ``session_id``: the shared session, or NULL for global."""
        if a.session_id and a.session_id == b.session_id:
            return a.session_id
        if a.session_id and not b.session_id:
            return a.session_id
        if b.session_id and not a.session_id:
            return b.session_id
        return None

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
                    defaults={
                        "mode": a.mode,
                        "session_id": edge_session(a, b),
                        "description": f"Shared algorithm family {family}",
                    },
                )
                if was:
                    created += 1

    # context: same location repo prefix
    by_repo: dict[str, list[CryptoAsset]] = {}
    for a in assets_list:
        if not a.location:
            continue  # Skip assets with no location — they share no context.
        repo = _context_repo(a.location)
        if not repo:
            continue
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
                    defaults={
                        "mode": a.mode,
                        "session_id": edge_session(a, b),
                        "description": "Share a deployment/context",
                    },
                )
                if was:
                    created += 1

    return created
