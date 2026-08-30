"""
CBOM Builder Component

Combines processed and validated cryptographic assets into a standardized CBOM document
complete with repository metadata, ISO timestamps, and summary statistics.
Supports returning Python dictionary objects and saving formatted JSON files.

NOTE: Excludes quantum risk metrics or PQC recommendations to allow clean downstream module consumption.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Union


class CBOMBuilder:
    """
    Assembles repository metadata, summary statistics, and cryptographic assets into a final CBOM document.
    """

    def __init__(self, format_name: str = "ECDAT-CBOM", version: str = "1.0"):
        self.format_name = format_name
        self.version = version

    def build(
        self,
        repository: Optional[Dict[str, Any]] = None,
        crypto_assets: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Builds a complete CBOM dictionary object.

        :param repository: Repository metadata dictionary.
        :param crypto_assets: List of validated cryptographic asset dictionaries.
        :return: Final CBOM dictionary object.
        """
        repo_data = repository or {}
        assets_data = crypto_assets or []

        # 1. Compute summary statistics
        total_assets = len(assets_data)
        confirmed_count = sum(
            1 for a in assets_data if a.get("validation_status") == "confirmed"
        )
        partial_count = sum(
            1 for a in assets_data if a.get("validation_status") == "partial"
        )
        needs_review_count = sum(
            1 for a in assets_data if a.get("validation_status") == "needs_review"
        )
        invalid_count = sum(
            1 for a in assets_data if a.get("validation_status") == "invalid"
        )

        # 2. Compute family counts
        family_counts = {
            "asymmetric": 0,
            "symmetric": 0,
            "hash": 0,
            "protocol": 0,
            "other": 0,
        }

        for asset in assets_data:
            fam = str(asset.get("family") or "").lower()
            if fam in family_counts:
                family_counts[fam] += 1
            else:
                family_counts["other"] += 1

        # 3. Construct ISO 8601 timestamp
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        cbom_document: Dict[str, Any] = {
            "format": self.format_name,
            "version": self.version,
            "generated_at": generated_at,
            "repository": {
                "name": repo_data.get("name"),
                "url": repo_data.get("url"),
            },
            "summary": {
                "total_assets": total_assets,
                "confirmed_assets": confirmed_count,
                "partial_assets": partial_count,
                "needs_review_assets": needs_review_count,
                "invalid_assets": invalid_count,
                "by_family": family_counts,
            },
            "crypto_assets": assets_data,
        }

        return cbom_document

    def save_json(
        self, cbom_doc: Dict[str, Any], output_path: Union[str, Path]
    ) -> Path:
        """
        Saves the CBOM dictionary object to a JSON file.

        :param cbom_doc: CBOM document dictionary.
        :param output_path: Destination filepath.
        :return: Path object of the saved file.
        """
        filepath = Path(output_path)
        filepath.parent.mkdir(parents=True, exist_ok=True)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(cbom_doc, f, indent=2, ensure_ascii=False)

        return filepath
