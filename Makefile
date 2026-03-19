.PHONY: all install test lint format check clean dist

all: check test

install:
	uv sync

test:
	uv run python -m pytest tests/ -v

lint:
	uv run ruff check src/pyaegis/ tests/

format:
	uv run ruff format src/pyaegis/ tests/

check: lint
	uv run ruff format --check src/pyaegis/ tests/

clean:
	rm -rf dist/ build/ __pycache__ src/pyaegis/__pycache__ tests/__pycache__ .pytest_cache src/*.egg-info
	find . -name '*.pyc' -delete

dist: clean
	uv build
