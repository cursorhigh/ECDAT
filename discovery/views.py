"""Function views for the discovery app (action endpoints)."""

import json
import os

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .models import ScanJob
from .serializers import ScanJobSerializer


@csrf_exempt
def browse(request):
    """List local folders/drives for the path picker (GET).

    ?path=       -> list the subfolders of that folder (default: roots/drives)
    Returns any readable path on this machine. ECDAT runs locally, so this is
    a genuine path browser -- nothing is uploaded.
    """
    if request.method != "GET":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    path = (request.GET.get("path") or "").strip()

    if not path:
        # Return the available roots (drives on Windows, "/" on POSIX).
        return JsonResponse({"path": "", "parent": None, "folders": _list_roots()})

    path = os.path.abspath(os.path.expanduser(path))
    if not os.path.isdir(path):
        return JsonResponse({"detail": f"Not a directory: {path}"}, status=400)

    folders = []
    try:
        entries = sorted(os.scandir(path), key=lambda e: e.name.lower())
    except PermissionError:
        return JsonResponse({"path": path, "parent": None, "folders": [], "error": "Access denied"})

    for entry in entries:
        try:
            if entry.is_dir() and not entry.name.startswith("$"):
                folders.append(entry.name)
        except OSError:
            continue

    parent = os.path.dirname(path) if path != os.path.dirname(path) else None
    return JsonResponse({"path": path, "parent": parent or "", "folders": folders})


def _list_roots():
    if os.name == "nt":
        import string

        from ctypes import windll

        roots = []
        drives = []
        bitmask = windll.kernel32.GetLogicalDrives()
        for letter in string.ascii_uppercase:
            if bitmask & 1:
                drives.append(f"{letter}:\\")
            bitmask >>= 1
        for drive in drives:
            if os.path.isdir(drive):
                roots.append(drive)
        return roots
    return ["/"]


@csrf_exempt
def scan_preview(request):
    """Return the platform and the roots a given scan scope will walk (GET).

    ?scan_type=quick|whole|specified
    Lets the Discovery page explain what a Quick/Whole scan will actually
    cover on this machine before the user clicks Start.
    """
    from types import SimpleNamespace

    from .scanners.platform import detect_platform, resolve_scan_roots

    if request.method != "GET":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    scan_type = (request.GET.get("scan_type") or "quick").strip().lower()
    if scan_type not in ("quick", "whole", "specified"):
        return JsonResponse({"detail": f"Unknown scan type '{scan_type}'."}, status=400)

    job = SimpleNamespace(config={"scan_type": scan_type}, target=scan_type)
    roots = resolve_scan_roots(job)
    return JsonResponse(
        {
            "platform": detect_platform(),
            "scan_type": scan_type,
            "roots": [
                {"root": r.root, "label": r.label, "scan_all": r.scan_all} for r in roots
            ],
        }
    )


@csrf_exempt
def run_demo_scan(request):
    """Trigger the demo-mode scan (POST) and return the created ScanJob."""
    from .services import run_demo_scan as create_and_run

    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    job = create_and_run()
    return JsonResponse(ScanJobSerializer(job).data, status=201)


@csrf_exempt
def start_scan(request):
    """Start a scan with user-supplied parameters (POST).

    Body (JSON): {
        "scan_type": "quick" | "whole" | "specified",
        "source_type": "source_code",
        "target": "folder path (only for specified scan)",
        "options": { "<option>": true }
    }
    """
    from .services import ScanInspectionError, create_and_run_scan

    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    try:
        payload = json.loads(request.body or b"{}")
    except ValueError:
        return JsonResponse({"detail": "Invalid JSON body"}, status=400)

    source_type = payload.get("source_type", ScanJob.SourceType.SOURCE_CODE)
    target = payload.get("target", "")
    scan_type = payload.get("scan_type", "specified")
    options = payload.get("options") or {}

    try:
        job = create_and_run_scan(
            source_type=source_type,
            target=target,
            config=options,
            scan_type=scan_type,
        )
    except ScanInspectionError as exc:
        return JsonResponse({"detail": str(exc)}, status=400)

    return JsonResponse(ScanJobSerializer(job).data, status=201)


@csrf_exempt
def scan_data(request):
    """Accept externally-supplied scan data (POST) and ingest it as findings.

    Lets an external scanner hand raw findings straight to ECDAT instead of
    having the app walk a local folder. Body (JSON):
        {
            "source_type": "source_code",
            "target": "optional label for the data source",
            "findings": [ { ...raw finding dict... }, ... ]
        }
    Each `findings` element follows the raw-finding schema used by the
    built-in scanners (see discovery/scanners/base.py). The normalizer,
    classifier and correlator then run exactly as for a folder scan.
    """
    from .services import ScanInspectionError, ingest_external_findings

    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    try:
        payload = json.loads(request.body or b"{}")
    except ValueError:
        return JsonResponse({"detail": "Invalid JSON body"}, status=400)

    findings = payload.get("findings")
    if not isinstance(findings, list):
        return JsonResponse({"detail": "`findings` must be a JSON array."}, status=400)

    try:
        job = ingest_external_findings(
            source_type=payload.get("source_type", ""),
            findings=findings,
            target=payload.get("target", ""),
        )
    except ScanInspectionError as exc:
        return JsonResponse({"detail": str(exc)}, status=400)

    return JsonResponse(ScanJobSerializer(job).data, status=201)


