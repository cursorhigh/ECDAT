"""Handoff contract: delivered report payload.

Boundary:  reporting -> user (web layer)
Storage:   none — generated on request, never persisted server-side.

Documentation-of-record: the runtime pipeline is not wired to this contract
yet (see schema/README.md). It mirrors the JSON returned by
`reports.views.full_report_json`.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


class ReportDeliveryPayload(BaseModel):
    """Body handed to the front-end for download / preview."""

    format: Literal["pdf", "html"]
    filename: str
    mime: str
    size: int
    b64: str = Field(..., description="Base64-encoded PDF or HTML bytes (ASCII).")
    generated_at: str = ""
    render_error: Optional[str] = None
    scope: str = ""