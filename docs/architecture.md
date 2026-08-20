# Architecture

`identity-service` is a single-process FastAPI application with a synchronous SQLAlchemy 2 and
psycopg 3 persistence layer. The package uses a compact `src/identity_service` layout:

- `config` validates the environment boundary, including the deployed single-host PostgreSQL
  TCP/TLS destination contract while retaining deliberate local/test Unix-socket support.
- `models` defines the authoritative `identity` schema mapping.
- `services` owns internal identity bootstrap, profile read, and display-name update transactions.
- `db` creates lazy engines/sessions and checks the packaged migration revision.
- `api` exposes operational routes and request-boundary middleware.
- `observability` centralizes bounded metrics and the shared redacted application/Uvicorn logging
  pipeline.

No database connection is opened at module import. Application lifespan constructs a lazy engine
and disposes it during shutdown. Each service operation owns one session and one transaction;
exceptions roll it back. The runtime process never invokes Alembic or DDL.

The persistence stack is intentionally synchronous. Readiness is therefore a normal synchronous
FastAPI path operation, which the framework dispatches to its worker pool, keeping connection
attempts, pool waits, and SQL off the Uvicorn event loop. Every future HTTP path that calls
synchronous SQLAlchemy must retain an equivalent thread-pool boundary.

## Identity flow

An already-validated future authentication adapter will supply strict `ProviderIdentityInput` and
`ProviderProfileInput` values to `bootstrap_identity`. The service does not currently supply that
adapter or expose identity/profile operations through HTTP.

Bootstrap derives a signed 64-bit PostgreSQL advisory-lock key from the first eight bytes of
`SHA-256(issuer UTF-8 + NUL + subject UTF-8)`. It takes a transaction-scoped advisory lock, re-queries
the exact pair, and creates or synchronizes the three rows atomically. The unique `(issuer, subject)`
constraint remains the final correctness backstop.

The application has no Redis, upstream HTTP call, background worker, event bus, browser state,
roles/permissions model, or generic administration surface.

## Infrastructure boundary

The repository owns application source, schema migrations, tests, a disposable local Compose path,
and a production image definition. `platform-infrastructure` owns AWS/Cognito, Google, DNS,
certificates, network exposure, production PostgreSQL provisioning and roles, backups/restores,
Nginx, deployment, and runtime secret delivery. No production cloud resource is created here.
