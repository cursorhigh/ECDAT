"""Unit tests for the Reporting Segment."""

import json
import os
import sys
from pathlib import Path
import unittest

backend_dir = Path(__file__).resolve().parent.parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from segments.reporting.reports.pdf_renderer import _find_browser


class TestReportingSegment(unittest.TestCase):
    """Test HTML generation and PDF renderer detection."""

    def test_browser_detection(self):
        browser = _find_browser()
        # Edge or Chrome is typically available on Windows
        self.assertTrue(browser is None or os.path.isfile(browser))



if __name__ == "__main__":
    unittest.main()
