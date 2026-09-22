.PHONY: check lint test build

check: lint test

lint:
	uv run ruff check .
	uv run ruff format --check .
	uv run bandit -r src/
	uv run mypy
	uvx ty check src tests

test:
	uv run python setup.py build_ext --inplace
	uv run pytest
	CBORX_DISABLE_FAST=1 uv run pytest --cov --cov-report=term-missing

build:
	uv build
