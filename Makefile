.PHONY: setup sync dev build test test-python test-ui notebook-check check audit clean

UV ?= uv
UV_RUN = $(UV) run --frozen

setup:
	$(UV) sync --locked --extra contributor
	cd app && npm ci

sync:
	$(UV) sync --locked --extra contributor
	cd app && npm ci

dev:
	cd app && npm run dev

build:
	cd app && npm run build:pages

test: test-python test-ui

test-python:
	$(UV_RUN) pytest -q
	$(UV_RUN) python scripts/run_labs.py
	$(UV_RUN) python scripts/validate_notebooks.py
	$(UV_RUN) python scripts/check_links.py

notebook-check:
	$(UV_RUN) python scripts/execute-notebooks.py --timeout 90

test-ui:
	cd app && npm test

check:
	$(UV) lock --check
	$(UV_RUN) python -m compileall -q curriculum scripts tests
	$(MAKE) test
	$(MAKE) notebook-check

audit:
	$(UV) audit --locked --preview-features audit-command
	cd app && npm audit --audit-level=high

clean:
	rm -rf out app/node_modules .pytest_cache
	find curriculum scripts tests -type d -name __pycache__ -prune -exec rm -rf {} +
