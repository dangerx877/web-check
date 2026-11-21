.PHONY: install test cov lint typecheck run serve e2e
install:
	python -m pip install -e ".[dev]"
test:
	python -m pytest
cov:
	python -m pytest --cov --cov-report=term-missing
lint:
	ruff check .
typecheck:
	mypy netcommander
run:
	python -m netcommander
serve:
	python -m netcommander serve --user $(USER_EMAIL)
e2e:
	python tests/e2e/demo_server.py /tmp/nc-demo 8799 & sleep 3; node tests/e2e/ui_smoke.cjs http://127.0.0.1:8799/ /tmp/nc-demo/demo-credentials.json /tmp; kill %1
