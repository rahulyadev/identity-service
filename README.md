# identity-service

Identity service to store user data. The service currently provides a PostgreSQL identity model, a
concurrency-safe internal identity/profile service, operational HTTP endpoints, migrations,
observability, local containers, and automated checks.

The service does not provide Cognito or Google token validation, browser login, callback, session,
cookie, logout, or a `/v1/me` endpoint. The only HTTP surface is operational.

## Current contract

- Every local user has an application-generated UUIDv4 that remains stable across provider profile
  changes.
- Provider identities resolve only by the exact, case-sensitive `(issuer, subject)` pair. Subjects
  are opaque text; email is profile data and is never an identity key.
- PostgreSQL is authoritative. Redis is not used.
- Provider-owned profile fields are replaced by the latest supplied internal snapshot; omitted
  optional fields are cleared. A user-owned display-name override is preserved.
- The internal service rejects disabled and deleted users. There is no public deletion or export
  API or deletion/scrubbing workflow.

See [architecture](docs/architecture.md), [data model](docs/data-model.md),
[security](docs/security.md), [migrations](docs/migrations.md), and
[operations](docs/operations.md) for the detailed boundaries.

## Requirements and locked install

- Python exactly `3.14.4`
- Docker with Compose for PostgreSQL and full validation
- GNU Make

The repository uses a project-local virtual environment and pip-tools-generated lock files with
SHA-256 hashes. It does not install global Python tools. The bootstrap downloads one exact pip
wheel and verifies its committed SHA-256 before extracting it into `.venv`.

```sh
make sync
```

`requirements.lock` is the production dependency set. `requirements-dev.lock` contains the exact
validation toolchain. Regenerate both with `make lock` and review the diff.

## Local PostgreSQL and application

The Compose credentials are fixed, obvious local-only values. Never reuse them outside the
disposable local environment.

```sh
make db-up
make migrate
make app-up
curl --fail http://localhost:8080/health/live
curl --fail http://localhost:8080/health/ready
```

Migrations run explicitly as `identity_service_migrator`; the application runs as
`identity_service_app`. Application startup never runs DDL. Stop the stack and remove only its
named disposable volume with:

```sh
make db-down
```

## Developer commands

```text
make sync              install the hash-locked development set locally
make lock-check        compare both locks with fresh hash-locked resolutions
make pip-check         verify the installed environment is consistent
make format            format and apply safe lint fixes
make format-check      check formatting without changes
make lint              run Ruff
make typecheck         run strict mypy
make test-unit         run unit tests
make test-contract     run HTTP/OpenAPI contract tests
make test-security     run focused security tests
make test-integration  run PostgreSQL service tests
make test-migrations   run disposable upgrade/downgrade/re-upgrade tests
make coverage          enforce branch-aware 90% overall coverage
make openapi           regenerate openapi/openapi.json
make openapi-check     compare generated OpenAPI with the committed artifact
make sbom              generate the runtime dependency CycloneDX JSON under .cache/security
make sbom-check        validate the SBOM component set against requirements.lock
make security          dependency audit, SBOM, documentation, secret, and Bandit checks
make docker-build      build the production runtime image
make docker-smoke      test the packed image, outage recovery, hardening, and shutdown
make validate-offline  run checks that need no PostgreSQL or application container
make validate-local    run the complete local validation sequence
make validate          alias the complete local validation sequence
```

Database test commands require the three `TEST_*_DATABASE_URL` values used by the Makefile. They
fail rather than substituting SQLite or skipping required tests. `make validate-offline` makes no
release-readiness claim. Both `make validate-local` and `make validate` require Docker immediately,
then run PostgreSQL migrations, every test class, full branch coverage, the production-image build,
and packed-image smoke checks; neither can succeed after only the offline subset.

## Runtime dependency SBOM

`make sbom-check` generates and semantically validates a CycloneDX JSON inventory from the exact
packages in `requirements.lock`. Packages that exist only in `requirements-dev.lock` are excluded,
and the check rejects stale components, credentials, private repository references, and local
workspace paths. Normal output is written beneath the ignored `.cache/security` directory.

This Python runtime SBOM does not inventory operating-system or container-image packages.
Infrastructure or release automation may later combine it with an independently generated
image-level SBOM.

## Operational endpoints

| Method | Path | Behavior |
| --- | --- | --- |
| `GET` | `/health/live` | Process/application liveness only; never queries PostgreSQL. |
| `GET` | `/health/ready` | `200` only after `SELECT 1` succeeds and the one stored Alembic revision equals the packaged head; otherwise safe `503`. |
| `GET` | `/metrics` | Prometheus metrics when `METRICS_ENABLED=true`; intended for infrastructure-restricted access. |
| `GET` | `/openapi.json` | Generated OpenAPI document. |

Swagger UI and ReDoc may be enabled only in local/test environments and are forbidden in deployed
development, staging, and production. Their local HTML uses the default external static assets and
therefore omits the API-only CSP; JSON, metrics, problem, and operational responses retain the
restrictive policy. `/openapi.json` is the stable machine-readable contract. There is deliberately
no CORS middleware because direct application-browser access is unsupported.

Every failure body uses `application/problem+json` and the public fields `type`, `title`, `status`,
`detail`, `request_id`, and `code`. Stable `code` examples include `not_ready`, `body_too_large`,
and `internal_error`. The internal structured-log field remains `error_code`; it is not part of the
HTTP contract.

## Configuration

Configuration comes from environment variables. `DATABASE_URL` is required, treated as secret,
and redacted from settings representations and logs. `ALLOWED_HOSTS` and `TRUSTED_PROXY_CIDRS`
use JSON-array encoding, for example `ALLOWED_HOSTS='["identity.test","localhost"]'`.

| Variable | Local default / rule |
| --- | --- |
| `APP_ENV` | `local`; supported: local, test, development, staging, production |
| `SERVICE_VERSION` | `0.1.0` |
| `PORT` | `8080` |
| `IDENTITY_ORIGIN` | scheme, host, and optional port only; deployed environments require HTTPS |
| `ALLOWED_HOSTS` | exact DNS/IPv4 hosts or `*.example` subdomains; origin host must match |
| `TRUSTED_PROXY_CIDRS` | strict-network JSON array; deployed trust-all networks are rejected |
| `MAX_REQUEST_BODY_BYTES` | `16384`; streamed bytes are counted |
| `LOG_LEVEL` | `INFO`; deployed development/staging/production reject `DEBUG` |
| `LOG_FORMAT` | `console`; deployed development/staging/production require `json` |
| `METRICS_ENABLED` | `true` |
| `DATABASE_URL` | required `postgresql+psycopg` URL; deployed environments require one explicit authority TCP host and exactly one `sslmode=verify-full`; no source default |
| `DB_POOL_SIZE` / `DB_MAX_OVERFLOW` | `5` / `10` |
| `DB_POOL_TIMEOUT_SECONDS` | `5` |
| `DB_POOL_RECYCLE_SECONDS` | `1800` |
| `DB_STATEMENT_TIMEOUT_MS` | `2000` |
| `DB_CONNECT_TIMEOUT_SECONDS` | `3` |
| `GRACEFUL_SHUTDOWN_SECONDS` | `15` |
| `ENABLE_INTERACTIVE_DOCS` | `true` locally; must be `false` in deployed environments |

Development, staging, and production database URLs must contain exactly one explicit DNS, IPv4, or
bracketed IPv6 authority host, an optional authority port in `1..65535`, and exactly one
`sslmode=verify-full`. Query `host`, `hostaddr`, `port`, `service`, and `servicefile` routing is
rejected, as are Unix-domain sockets and multiple destinations. `sslmode=verify-full` alone does
not establish this contract when the connection can be redirected to a local socket. Local and
test environments may deliberately use a Unix-domain socket. Invalid settings fail application
construction without echoing the URL.

## Ownership boundary

This repository creates no production cloud resources. AWS/Cognito, Google configuration, DNS,
certificates, production databases, backups, restore execution, Nginx, and deployment belong to
`platform-infrastructure`. This service defines the database schema and restore compatibility;
platform owners operate and test backups and restores. CI requires no cloud or repository secrets
and performs no deployment.

GitHub Actions use current official major release tags (`actions/checkout@v7` and
`actions/setup-python@v7`). Major tags permit upstream security maintenance while keeping breaking
changes reviewable.
