"""PDF rendering — brings an ECDAT report HTML document to a PDF byte string.

Renders entirely client-side tooling (headless Chromium) so the PDF is produced
on-demand and returned to the front-end (base64) without ever being persisted.
Falls back across candidate engine paths in order.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile

logger = logging.getLogger(__name__)

_CHROMIUM_CANDIDATES = [
    os.environ.get("ECDAT_CHROMIUM"),
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
]

_EDGE_HEADLESS_ARGS = [
    "--headless=new",
    "--disable-gpu",
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--no-pdf-header-footer",
    "--print-to-pdf-no-header",
    "--hide-scrollbars",
    "--run-all-compositor-stages-before-draw",
    "--virtual-time-budget=5000",
]


def _find_browser() -> str | None:
    for cand in _CHROMIUM_CANDIDATES:
        if cand and os.path.isfile(cand):
            return cand
    for name in ("msedge", "chrome", "chromium", "chromium-browser"):
        path = shutil.which(name)
        if path:
            return path
    return None


def render_pdf(html: str) -> bytes:
    """Render ``html`` to PDF bytes via headless Chromium.

    Raises ``RuntimeError`` when no usable browser is available.
    """
    browser = _find_browser()
    if not browser:
        raise RuntimeError(
            "No Chromium/Edge browser found for PDF rendering. "
            "Install Edge/Chrome or set ECDAT_CHROMIUM to the binary path."
        )

    tmp = tempfile.mkdtemp(prefix="ecdat_report_")
    html_path = os.path.join(tmp, "report.html")
    pdf_path = os.path.join(tmp, "report.pdf")
    try:
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(html)
        cmd = [browser, *(_EDGE_HEADLESS_ARGS.copy()), f"--print-to-pdf={pdf_path}", html_path]
        proc = subprocess.run(cmd, capture_output=True, timeout=90)
        try:
            proc.check_returncode()
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(f"PDF renderer exited {proc.returncode}") from exc
        with open(pdf_path, "rb") as fh:
            data = fh.read()
        if not data:
            raise RuntimeError("PDF renderer produced an empty document")
        return data
    finally:
        shutil.rmtree(tmp, ignore_errors=True)