PYTHON := .venv/bin/python
PIP := $(PYTHON) -m pip
COMPOSE := docker compose
export PIP_CACHE_DIR := $(CURDIR)/.cache/pip
export PIP_TOOLS_CACHE_DIR := $(CURDIR)/.cache/pip-tools
export DOCKER_CONFIG := $(CURDIR)/.cache/docker
LOCAL_APP_DATABASE_URL := postgresql+psycopg://identity_service_app:localapp@localhost:55432/identity_service # pragma: allowlist secret (fixed disposable local credential)
LOCAL_MIGRATOR_DATABASE_URL := postgresql+psycopg://identity_service_migrator:localmigrator@localhost:55432/identity_service # pragma: allowlist secret (fixed disposable local credential)
LOCAL_ADMIN_DATABASE_URL := postgresql+psycopg://postgres:localpostgres@localhost:55432/postgres # pragma: allowlist secret (fixed disposable local credential)
TEST_DATABASE_URLS := TEST_DATABASE_URL=$(LOCAL_APP_DATABASE_URL) TEST_MIGRATOR_DATABASE_URL=$(LOCAL_MIGRATOR_DATABASE_URL) TEST_DATABASE_ADMIN_URL=$(LOCAL_ADMIN_DATABASE_URL)
SBOM_PATH ?= $(CURDIR)/.cache/security/identity-service-runtime.cdx.json

.PHONY: bootstrap lock lock-check sync pip-check format format-check lint typecheck test-unit test-integration \
	test-migrations test-contract test-security test-all coverage openapi openapi-check security \
	dependency-audit secret-scan static-security public-docs-check sbom sbom-check \
	migration-heads migration-drift db-up db-down \
	migrate app-up docker-build docker-smoke check-local-prerequisites validate-offline \
	validate-local validate

bootstrap:
	python3 scripts/bootstrap_venv.py

lock: bootstrap
	$(PIP) install pip-tools==7.6.1
	$(PYTHON) -m piptools compile --generate-hashes --allow-unsafe --strip-extras --resolver=backtracking --output-file=requirements.lock requirements.in
	$(PYTHON) -m piptools compile --generate-hashes --allow-unsafe --strip-extras --resolver=backtracking --output-file=requirements-dev.lock requirements-dev.in

lock-check:
	$(PYTHON) scripts/check_locks.py

sync: bootstrap
	$(PIP) install --require-hashes --no-deps -r requirements-dev.lock
	$(PIP) install --no-deps --no-build-isolation --editable .

pip-check:
	$(PIP) check

format:
	$(PYTHON) -m ruff format .
	$(PYTHON) -m ruff check --fix .

format-check:
	$(PYTHON) -m ruff format --check .

lint:
	$(PYTHON) -m ruff check .

typecheck:
	$(PYTHON) -m mypy

test-unit:
	$(PYTHON) -m pytest tests/unit -q

test-contract:
	$(PYTHON) -m pytest tests/contract -q

test-security:
	$(PYTHON) -m pytest tests/security -q

test-integration:
	@$(TEST_DATABASE_URLS) $(PYTHON) -m pytest tests/integration -m "not migration" -q

test-migrations:
	@$(TEST_DATABASE_URLS) $(PYTHON) -m pytest tests/integration -m migration -q

test-all:
	@$(TEST_DATABASE_URLS) $(PYTHON) -m pytest -q

coverage:
	@$(TEST_DATABASE_URLS) $(PYTHON) -m pytest --cov=identity_service --cov-branch --cov-report=term-missing --cov-report=xml -q

openapi:
	$(PYTHON) scripts/generate_openapi.py

openapi-check:
	$(PYTHON) scripts/generate_openapi.py --check

dependency-audit:
	$(PYTHON) -m pip_audit --cache-dir .cache/pip-audit --progress-spinner off --require-hashes --disable-pip -r requirements-dev.lock

secret-scan:
	$(PYTHON) scripts/check_secrets.py

static-security:
	$(PYTHON) -m bandit -c pyproject.toml -r src scripts

public-docs-check:
	$(PYTHON) scripts/check_public_docs.py

$(SBOM_PATH): requirements.lock
	@mkdir -p $(dir $(SBOM_PATH))
	$(PYTHON) -m pip_audit --cache-dir .cache/pip-audit --progress-spinner off --require-hashes --disable-pip -r requirements.lock --format cyclonedx-json --output $(SBOM_PATH)

sbom: $(SBOM_PATH)

sbom-check: sbom
	$(PYTHON) scripts/check_sbom.py --sbom $(SBOM_PATH)

security: dependency-audit secret-scan static-security public-docs-check sbom-check

migration-heads:
	$(PYTHON) scripts/check_migration_heads.py

migration-drift:
	@$(TEST_DATABASE_URLS) $(PYTHON) scripts/check_migration_drift.py

db-up:
	$(COMPOSE) up -d --wait db

migrate:
	$(COMPOSE) run --build --rm migrate

app-up:
	$(COMPOSE) up -d --wait app

db-down:
	$(COMPOSE) down --volumes --remove-orphans

docker-build:
	docker build --target runtime -t identity-service:local .

docker-smoke:
	$(PYTHON) scripts/container_smoke.py

check-local-prerequisites:
	@docker info >/dev/null 2>&1 || { echo "complete validation requires access to a running Docker daemon" >&2; exit 2; }
	@$(COMPOSE) version >/dev/null 2>&1 || { echo "complete validation requires Docker Compose" >&2; exit 2; }

validate-offline: lock-check pip-check format-check lint typecheck test-unit test-contract test-security openapi-check migration-heads security

validate-local: check-local-prerequisites
	$(MAKE) validate-offline
	$(MAKE) db-up
	$(MAKE) migrate
	$(MAKE) test-integration
	$(MAKE) test-migrations
	$(MAKE) migration-drift
	$(MAKE) coverage
	$(MAKE) docker-build
	$(MAKE) docker-smoke

validate: validate-local
