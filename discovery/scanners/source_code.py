"""Source-code scanner stub.

Production: this would run Semgrep with custom crypto rules against a
git repo. For this phase it provides a realistic deterministic pipeline
shape so the dashboard can be built and demoed.
"""

from ..models import ScanJob
from .base import BaseScanner


class SourceCodeScanner(BaseScanner):
    source_type = ScanJob.SourceType.SOURCE_CODE

    def run(self) -> list[dict]:
        # TODO: wire real Semgrep invocation here.
        return []
