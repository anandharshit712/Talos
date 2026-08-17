# Task entry points. Every target delegates to a script or a tool so that CI, pre-commit, and
# local runs execute identical logic. On Windows without `make`, use scripts/run_checks.ps1 or
# call the underlying commands directly.

PY ?= python
DB ?= talos.db
CHECKS := $(PY) tools/checks/run_all_checks.py

.DEFAULT_GOAL := help
.PHONY: help setup check check-structure check-naming check-size check-docs lint format types test gate migrate run

help:  ## show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

setup:  ## install the package in editable mode with dev extras, and wire pre-commit
	$(PY) -m pip install -e ".[dev]"
	pre-commit install

check-structure:  ## R1, R2
	$(PY) tools/checks/check_structure.py

check-naming:  ## R3, R4
	$(PY) tools/checks/check_naming.py

check-size:  ## R6
	$(PY) tools/checks/check_file_size.py

check-docs:  ## R5
	$(PY) tools/checks/check_feature_docs.py

lint:  ## ruff
	$(PY) -m ruff check .

format:  ## ruff format
	$(PY) -m ruff format .

types:  ## mypy
	$(PY) -m mypy

test:  ## pytest
	$(PY) -m pytest

check: check-structure check-naming check-size check-docs lint types test  ## the standard gate

gate:  ## the phase gate: adds the R3.5 test-mirror requirement
	$(CHECKS) --strict
	$(PY) -m ruff check .
	$(PY) -m mypy
	$(PY) -m pytest

migrate:  ## apply database migrations in timestamp order (DB=talos.db)
	$(PY) scripts/apply_migrations.py --db $(DB)

run: migrate  ## scan a log file through the pipeline (FILE=path/to.log)
	$(PY) -m talos.cli.main_cli scan $(FILE) --db $(DB)
