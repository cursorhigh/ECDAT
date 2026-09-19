"""Views for the crypto-discovery scan pipeline.

- start_scan: POST { path: "..." } -> walks FS, splits into N chunks,
  creates ScanChunk rows (pending), enqueues one huey task per chunk,
  returns { scan_id, chunks, ... }.
- scan_status: GET -> { scan_id, done, total, status }.
"""

import os

from django.db import transaction
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from .fs import split_paths_into_chunks, walk_scan_files
from .models import Scan, ScanChunk
from .pipeline import scan_chunk, _scan_complete_check


@csrf_exempt
def start_scan(request):
    """Start a crypto-discovery scan on a directory (POST).

    Body (JSON): { "path": "/absolute/dir/to/scan" }
    Walks the filesystem, splits the file list into N chunks (N = os.cpu_count()),
    persists ScanChunk rows (status=pending), enqueues one huey task per chunk,
    and returns the scan_id.
    """
    import json

    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    try:
        payload = json.loads(request.body or b"{}")
    except ValueError:
        return JsonResponse({"detail": "Invalid JSON body"}, status=400)

    path = (payload.get("path") or payload.get("target") or "").strip()
    if not path:
        return JsonResponse({"detail": "`path` is required."}, status=400)

    path = os.path.abspath(os.path.expanduser(path))
    if not os.path.isdir(path):
        return JsonResponse({"detail": f"Not a directory: {path}"}, status=400)

    try:
        file_paths = list(walk_scan_files(path))
    except NotADirectoryError as exc:
        return JsonResponse({"detail": str(exc)}, status=400)
    except OSError as exc:
        return JsonResponse({"detail": f"Failed to walk path: {exc}"}, status=400)

    n = max(1, os.cpu_count() or 1)
    chunks = split_paths_into_chunks(file_paths, n)

    from core.modes import active_db
    from core.sessions import create_scan_session

    ws = create_scan_session(request, os.path.basename(path.rstrip("\\/")) or path, using=active_db())

    with transaction.atomic():
        scan = Scan.objects.create(
            path=path,
            chunk_count=n,
            status=Scan.Status.PENDING,
            session_id=ws.pk,
        )
        for cid, files in enumerate(chunks):
            ScanChunk.objects.create(
                scan=scan, chunk_id=cid, status=ScanChunk.Status.PENDING, results=[]
            )

    # Mark scan running and enqueue one task per chunk.
    Scan.objects.filter(pk=scan.pk).update(
        status=Scan.Status.RUNNING, chunk_count=len(chunks)
    )
    for cid, files in enumerate(chunks):
        scan_chunk(scan.pk, cid, files)

    return JsonResponse(
        {
            "scan_id": scan.pk,
            "path": path,
            "total_chunks": len(chunks),
            "total_files": len(file_paths),
            "status": "running",
            "session": {"id": ws.pk, "name": ws.name},
        },
        status=201,
    )


def scan_status(request, scan_id: int):
    """Return scan progress (GET).

    Response: { "scan_id", "done", "total", "status" } where done/total are
    the completed-chunk count and total-chunk count respectively.
    """
    scan = Scan.objects.filter(pk=scan_id).first()
    if scan is None:
        return JsonResponse({"detail": "Scan not found."}, status=404)

    total = scan.chunk_count
    done = ScanChunk.objects.filter(
        scan_id=scan_id, status=ScanChunk.Status.DONE
    ).count()

    # Opportunistically reconcile status based on DB truth.
    current = scan.status
    if current != Scan.Status.COMPLETE and total > 0 and done >= total:
        _scan_complete_check(scan_id)
        current = Scan.Status.COMPLETE

    return JsonResponse(
        {
            "scan_id": scan_id,
            "done": done,
            "total": total,
            "status": current,
        }
    )


@csrf_exempt
def cancel_scan(request, scan_id):
    """Cancel a crypto-discovery scan (POST /crypto/scan/<id>/cancel/).

    Only pending/running scans are cancelled; their un-finished chunks are
    marked cancelled so the sweep recovery never resurrects them and the
    scan can never complete or forward a partial inventory.
    """
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    scan = Scan.objects.filter(pk=scan_id).first()
    if scan is None:
        return JsonResponse({"detail": "Scan not found."}, status=404)

    won = (
        Scan.objects.filter(
            pk=scan.pk,
            status__in=[Scan.Status.PENDING, Scan.Status.RUNNING],
        ).update(status=Scan.Status.CANCELLED)
    )
    if not won:
        return JsonResponse(
            {"detail": f"Scan {scan_id} is not cancellable (status: {scan.status})."},
            status=400,
        )
    ScanChunk.objects.filter(
        scan_id=scan.pk,
    ).exclude(status=ScanChunk.Status.DONE).update(status=ScanChunk.Status.CANCELLED)
    return JsonResponse({"scan_id": scan.pk, "status": Scan.Status.CANCELLED})
