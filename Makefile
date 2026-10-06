.PHONY: install dev lint security test check demo api docker clean

install:
	pip install -r requirements.txt

dev:
	pip install -r requirements-dev.txt

lint:
	ruff check .

security:
	bandit -q -c pyproject.toml -r phishir

test:
	pytest

check: lint security test

demo:
	python -m phishir analyze samples/*.eml -o cases/

api:
	uvicorn phishir.api:app --host 127.0.0.1 --port 8000

docker:
	docker build -t phishir:latest .

clean:
	rm -rf cases/ .pytest_cache .ruff_cache **/__pycache__
