.PHONY: install test cov lint typecheck run
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
