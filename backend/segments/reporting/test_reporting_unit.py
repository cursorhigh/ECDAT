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
from segments.reporting.demo_reporting import generate_executive_html


class TestReportingSegment(unittest.TestCase):
    """Test HTML generation and PDF renderer detection."""

    def test_browser_detection(self):
        browser = _find_browser()
        # Edge or Chrome is typically available on Windows
        self.assertTrue(browser is None or os.path.isfile(browser))

    def test_generate_executive_html_structure(self):
        ml_report = {
            "report_title": "Test Enterprise Report",
            "portfolio_stats": {
                "total_assets": 5,
                "high_risk_count": 3,
                "mosca_deficit_count": 2,
                "hndl_exposed_count": 2,
            },
            "executive_summary": "Test executive summary.",
        }
        mitigation_plan = {
            "summary": {"wave1": 2, "wave2": 2, "wave3": 1, "effort_estimate_quarters": 4},
            "waves": [{"name": "Wave 1", "timeline": "0-3m", "focus": "Urgent PQC", "asset_count": 2}],
            "rows": [
                {
                    "asset_id": "ASSET-1",
                    "algorithm": "RSA-2048",
                    "migration_wave": 1,
                    "migration_impact": {"replacement": "ML-KEM-768"},
                    "blast_radius": {"severity": "CRITICAL"},
                    "suggestions": ["Replace with ML-KEM-768"],
                }
            ],
        }

        html = generate_executive_html(ml_report, mitigation_plan)
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("RSA-2048", html)
        self.assertIn("ML-KEM-768", html)
        self.assertIn("Wave 1", html)
        self.assertIn("Test Enterprise Report", html)


if __name__ == "__main__":
    unittest.main()
