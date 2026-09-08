.PHONY: test lint security install-dev all

install-dev:
	pip install -r requirements.txt -r requirements-dev.txt

test:
	# DATABASE_URL is intentionally not set here: tests/conftest.py sets
	# SQLALCHEMY_DATABASE_URI to a per-session temp file regardless of this env var,
	# so setting it here would be misleading dead configuration.
	FLASK_SECRET_KEY=dev-secret \
	MSTDNCA_DATA_DIR=/tmp/mstdnca-dev \
	pytest tests/ -v --cov=. --cov-report=term-missing --cov-fail-under=40

lint:
	ruff check .

security:
	bandit -r . -c pyproject.toml
	pip-audit -r requirements.txt

all: lint security test
