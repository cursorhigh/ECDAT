# ECDAT developer tasks.
#   make help            list targets
#   make test            full Django test suite
#   make schema-docs     regenerate ownership matrix + ERD
#   make lint-imports    enforce segment boundaries (import-linter)

PY ?= python

.PHONY: help test test-scraping test-ml test-mitigation test-reporting schema-docs lint-imports

help:
	@echo "test             - run the full Django test suite"
	@echo "test-scraping    - discovery + crypto_scan (ingestion)"
	@echo "test-ml          - analysis app tests"
	@echo "test-mitigation  - mitigation app tests"
	@echo "test-reporting   - dashboard + reports tests"
	@echo "schema-docs      - regenerate schema ownership matrix + ERD"
	@echo "lint-imports     - enforce workstream segment boundaries"

test:
	$(PY) manage.py test

test-scraping:
	$(PY) manage.py test segments.scraping.discovery segments.scraping.crypto_scan

test-ml:
	$(PY) manage.py test segments.ml.analysis

test-mitigation:
	$(PY) manage.py test segments.mitigation.mitigation

test-reporting:
	$(PY) manage.py test segments.reporting.dashboard segments.reporting.reports

schema-docs:
	$(PY) scripts/generate_schema_docs.py

lint-imports:
	lint-imports