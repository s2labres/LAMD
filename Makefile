.PHONY: install setup-slicer lint java-check check build

install:
	uv sync

setup-slicer:
	./scripts/setup_slicer.sh

lint:
	uv run ruff check .
	uv run ruff format --check .

java-check:
	mvn --batch-mode --file java-slicer/pom.xml clean verify

check: lint java-check

build:
	uv build
