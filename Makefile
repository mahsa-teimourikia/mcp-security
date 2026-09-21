.PHONY: setup dev build test test-python test-ui notebook-check check clean

setup:
	python3 -m pip install -e '.[contributor]'
	cd app && npm ci

dev:
	cd app && npm run dev

build:
	cd app && npm run build:pages

test: test-python test-ui

test-python:
	python3 -m pytest -q
	python3 scripts/run_labs.py
	python3 scripts/validate_notebooks.py
	python3 scripts/check_links.py

notebook-check:
	python3 scripts/execute-notebooks.py --timeout 90

test-ui:
	cd app && npm test

check:
	python3 -m compileall -q curriculum scripts tests
	$(MAKE) test

clean:
	rm -rf out app/node_modules .pytest_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
