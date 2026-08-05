.DEFAULT_GOAL := help

UV ?= uv
API_VENV := apps/api/.venv
API_PYTHON := $(API_VENV)/bin/python

.PHONY: help install lock migrate publisher-migrate dev-api dev-worker dev-publisher dev-web lint test test-api test-web build generate-contract check-contract audit compose-config up publisher-up down logs

help: ## Show available commands
	@awk 'BEGIN {FS = ":.*## "; printf "Traceless commands:\n"} /^[a-zA-Z_-]+:.*## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install API and web development dependencies from lock files
	cd apps/api && $(UV) sync --locked --extra dev
	cd apps/web && npm ci

lock: ## Refresh Python and npm dependency lock files
	cd apps/api && $(UV) lock
	cd apps/web && npm install --package-lock-only

migrate: ## Apply customer-local database migrations
	cd apps/api && .venv/bin/python -m alembic upgrade head

publisher-migrate: ## Apply central publisher database migrations
	cd apps/api && .venv/bin/python -m alembic -c publisher_alembic.ini upgrade head

dev-api: ## Run the customer-local API on http://localhost:8000
	cd apps/api && .venv/bin/python -m uvicorn traceless_api.main:app --reload --host 0.0.0.0 --port 8000

dev-worker: ## Process scanner jobs (requires explicit scanner enablement)
	cd apps/api && .venv/bin/python -m traceless_api.worker

dev-publisher: ## Run the independent publisher on http://localhost:8100
	cd apps/api && .venv/bin/traceless-intelligence-publisher --host 0.0.0.0 --port 8100

dev-web: ## Run the web app on http://localhost:5173
	cd apps/web && npm run dev -- --host 0.0.0.0

lint: ## Run API static checks
	cd apps/api && .venv/bin/ruff check .

test: test-api test-web ## Run all automated tests

test-api: ## Run API and publisher tests
	cd apps/api && .venv/bin/python -m pytest --cov=traceless_api --cov-report=term-missing

test-web: ## Run web tests
	cd apps/web && npm run test

build: ## Type-check and build the web app
	cd apps/web && npm run build

generate-contract: ## Regenerate OpenAPI and the frontend's compile-time API contracts
	cd apps/api && .venv/bin/python scripts/export_openapi.py ../web/openapi.json
	cd apps/web && npm run generate:api

check-contract: generate-contract ## Fail when committed API contracts are stale
	git diff --exit-code -- apps/web/openapi.json apps/web/src/generated/traceless-api

audit: ## Check Python and npm dependencies for known vulnerabilities
	cd apps/api && $(UV) export --locked --extra dev --no-emit-project --format requirements-txt --output-file /tmp/traceless-audit-requirements.txt
	cd apps/api && .venv/bin/pip-audit --requirement /tmp/traceless-audit-requirements.txt --require-hashes
	cd apps/web && npm audit

compose-config: ## Validate the default and publisher Compose profiles
	docker compose config --quiet
	docker compose --profile publisher config --quiet

up: ## Build and start the customer-local stack
	docker compose up --build

publisher-up: ## Build and start only the central publisher profile
	docker compose --profile publisher up --build publisher

down: ## Stop all local services without deleting volumes
	docker compose --profile publisher down

logs: ## Follow local stack logs
	docker compose --profile publisher logs --follow
