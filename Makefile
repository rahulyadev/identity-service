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
BFF_TEST_REDIS_URL := redis://127.0.0.1:56379/15
SBOM_PATH ?= $(CURDIR)/.cache/security/identity-service-runtime.cdx.json
BFF_SBOM_PATH ?= $(CURDIR)/.cache/security/reference-bff-runtime.cdx.json

.PHONY: bootstrap lock lock-check sync pip-check format format-check lint typecheck test-unit test-integration \
	test-migrations test-contract test-security test-bff-unit test-bff-contract test-bff-security \
	test-bff-redis test-all coverage coverage-bff openapi openapi-check security \
	dependency-audit secret-scan static-security public-docs-check sbom sbom-check \
	bff-sbom bff-sbom-check migration-heads migration-drift db-up redis-up db-down \
	migrate app-up docker-build docker-smoke docker-build-bff docker-smoke-bff \
	check-local-prerequisites validate-offline \
	validate-local validate

bootstrap:
	python3 scripts/bootstrap_venv.py

lock: bootstrap
	$(PIP) install pip-tools==7.6.1
	$(PYTHON) -m piptools compile --generate-hashes --allow-unsafe --strip-extras --resolver=backtracking --output-file=requirements.lock requirements.in
	$(PYTHON) -m piptools compile --generate-hashes --allow-unsafe --strip-extras --resolver=backtracking --output-file=examples/reference_bff/requirements.lock examples/reference_bff/requirements.in
	$(PYTHON) -m piptools compile --generate-hashes --allow-unsafe --strip-extras --resolver=backtracking --output-file=requirements-dev.lock requirements-dev.in

lock-check:
	$(PYTHON) scripts/check_locks.py

sync: bootstrap
	$(PIP) install --require-hashes --no-deps -r requirements-dev.lock
	$(PIP) install --no-deps --no-build-isolation --editable .
	$(PIP) install --no-deps --no-build-isolation --editable examples/reference_bff

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

test-bff-unit:
	$(PYTHON) -m pytest tests/reference_bff/unit -q

test-bff-contract:
	$(PYTHON) -m pytest tests/reference_bff/contract -q

test-bff-security:
	$(PYTHON) -m pytest tests/reference_bff/security -q

test-bff-redis:
	@BFF_TEST_REDIS_URL=$(BFF_TEST_REDIS_URL) $(PYTHON) -m pytest tests/reference_bff/integration -q

test-integration:
	@$(TEST_DATABASE_URLS) $(PYTHON) -m pytest tests/integration -m "not migration" -q

test-migrations:
	@$(TEST_DATABASE_URLS) $(PYTHON) -m pytest tests/integration -m migration -q

test-all:
	@$(TEST_DATABASE_URLS) BFF_TEST_REDIS_URL=$(BFF_TEST_REDIS_URL) $(PYTHON) -m pytest -q

coverage:
	@$(TEST_DATABASE_URLS) $(PYTHON) -m pytest tests/unit tests/contract tests/security tests/integration --cov=identity_service --cov-branch --cov-report=term-missing --cov-report=xml -q

coverage-bff:
	@BFF_TEST_REDIS_URL=$(BFF_TEST_REDIS_URL) $(PYTHON) -m pytest tests/reference_bff --cov=reference_bff --cov-branch --cov-report=term-missing --cov-report=xml:.cache/coverage/reference-bff.xml --cov-fail-under=90 -q

openapi:
	$(PYTHON) scripts/generate_openapi.py

openapi-check:
	$(PYTHON) scripts/generate_openapi.py --check

dependency-audit:
	$(PYTHON) -m pip_audit --cache-dir .cache/pip-audit --progress-spinner off --require-hashes --disable-pip -r requirements-dev.lock
	$(PYTHON) -m pip_audit --cache-dir .cache/pip-audit --progress-spinner off --require-hashes --disable-pip -r examples/reference_bff/requirements.lock

secret-scan:
	$(PYTHON) scripts/check_secrets.py

static-security:
	$(PYTHON) -m bandit -c pyproject.toml -r src scripts examples/reference_bff/src examples/reference_bff/scripts

public-docs-check:
	$(PYTHON) scripts/check_public_docs.py

$(SBOM_PATH): requirements.lock
	@mkdir -p $(dir $(SBOM_PATH))
	$(PYTHON) -m pip_audit --cache-dir .cache/pip-audit --progress-spinner off --require-hashes --disable-pip -r requirements.lock --format cyclonedx-json --output $(SBOM_PATH)

sbom: $(SBOM_PATH)

sbom-check: sbom
	$(PYTHON) scripts/check_sbom.py --sbom $(SBOM_PATH)

$(BFF_SBOM_PATH): examples/reference_bff/requirements.lock
	@mkdir -p $(dir $(BFF_SBOM_PATH))
	$(PYTHON) -m pip_audit --cache-dir .cache/pip-audit --progress-spinner off --require-hashes --disable-pip -r examples/reference_bff/requirements.lock --format cyclonedx-json --output $(BFF_SBOM_PATH)

bff-sbom: $(BFF_SBOM_PATH)

bff-sbom-check: bff-sbom
	$(PYTHON) scripts/check_sbom.py --sbom $(BFF_SBOM_PATH) --runtime-lock examples/reference_bff/requirements.lock --development-lock requirements-dev.lock

security: dependency-audit secret-scan static-security public-docs-check sbom-check bff-sbom-check

migration-heads:
	$(PYTHON) scripts/check_migration_heads.py

migration-drift:
	@$(TEST_DATABASE_URLS) $(PYTHON) scripts/check_migration_drift.py

db-up:
	$(COMPOSE) up -d --wait db

redis-up:
	$(COMPOSE) up -d --wait redis

migrate:
	$(COMPOSE) run --build --rm migrate

app-up:
	$(COMPOSE) up -d --wait app

db-down:
	$(COMPOSE) down --volumes --remove-orphans

docker-build:
	docker build --target runtime -t identity-service:local .

docker-smoke:
	$(PYTHON) -m scripts.container_smoke

docker-build-bff:
	docker build --file examples/reference_bff/Dockerfile --target runtime -t reference-bff:local .

docker-smoke-bff:
	$(PYTHON) examples/reference_bff/scripts/container_smoke.py

check-local-prerequisites:
	@docker info >/dev/null 2>&1 || { echo "complete validation requires access to a running Docker daemon" >&2; exit 2; }
	@$(COMPOSE) version >/dev/null 2>&1 || { echo "complete validation requires Docker Compose" >&2; exit 2; }

validate-offline: lock-check pip-check format-check lint typecheck test-unit test-contract test-security test-bff-unit test-bff-contract test-bff-security openapi-check migration-heads security

validate-local: check-local-prerequisites
	$(MAKE) validate-offline
	$(MAKE) db-up
	$(MAKE) redis-up
	$(MAKE) migrate
	$(MAKE) test-integration
	$(MAKE) test-migrations
	$(MAKE) test-bff-redis
	$(MAKE) migration-drift
	$(MAKE) coverage
	$(MAKE) coverage-bff
	$(MAKE) docker-build
	$(MAKE) docker-smoke
	$(MAKE) docker-build-bff
	$(MAKE) docker-smoke-bff

validate:
	@status=0; \
	$(MAKE) validate-local || status=$$?; \
	cleanup_status=0; \
	$(COMPOSE) down --volumes --remove-orphans || cleanup_status=$$?; \
	if [ $$status -ne 0 ]; then exit $$status; fi; \
	if [ $$cleanup_status -ne 0 ]; then exit $$cleanup_status; fi
