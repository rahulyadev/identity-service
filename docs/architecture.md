# Architecture

`identity-service` is a single-process FastAPI application with a synchronous SQLAlchemy 2 and
psycopg 3 persistence layer. The package uses a compact `src/identity_service` layout:

- `config` validates the environment boundary, including the deployed single-host PostgreSQL
  TCP/TLS destination contract while retaining deliberate local/test Unix-socket support.
- `models` defines the authoritative `identity` schema mapping.
- `services` owns internal identity bootstrap, profile read, and display-name update transactions.
- `db` creates lazy engines/sessions and checks the packaged migration revision.
- `api` exposes operational routes, the authenticated v1 profile adapter, and request-boundary
  middleware.
- `observability` centralizes bounded metrics and the shared redacted application/Uvicorn logging
  pipeline.
- `security` owns the fixed-RS256 access-token verifier, single-flight bounded JWKS cache, shared
  upstream HTTP boundary, immutable verified-token contract, and subject-bound UserInfo adapter.

No database connection is opened at module import. Application lifespan constructs a lazy engine
and disposes it during shutdown. Each service operation owns one session and one transaction;
exceptions roll it back. The runtime process never invokes Alembic or DDL.

The persistence stack is intentionally synchronous. Readiness is therefore a normal synchronous
FastAPI path operation, which the framework dispatches to its worker pool, keeping connection
attempts, pool waits, and SQL off the Uvicorn event loop. Every future HTTP path that calls
synchronous SQLAlchemy must retain an equivalent thread-pool boundary.

## Identity flow

The profile HTTP adapter validates a Cognito access token before route-specific input, then binds a
bounded UserInfo profile to the token's exact subject for `PUT /v1/me`. It supplies strict
`ProviderIdentityInput` and `ProviderProfileInput` values to the existing transactional service.
`GET /v1/me` resolves the exact verified issuer/subject locally and never calls UserInfo.
`PATCH /v1/me` parses a strict profile ETag and duplicate-sensitive merge-patch document before
calling the existing atomic display-name update.

Bootstrap derives a signed 64-bit PostgreSQL advisory-lock key from the first eight bytes of
`SHA-256(issuer UTF-8 + NUL + subject UTF-8)`. It takes a transaction-scoped advisory lock, re-queries
the exact pair, and creates or synchronizes the three rows atomically. The unique `(issuer, subject)`
constraint remains the final correctness backstop.

The single process owns one synchronous, no-proxy/no-redirect upstream HTTP client. Application
startup remains network-independent; readiness may perform a bounded JWKS fetch on a worker thread.
Profile authentication, UserInfo, and PostgreSQL route work uses synchronous FastAPI path operations
and therefore remains in the framework worker pool. The application has no Redis, background worker,
event bus, browser state, roles/permissions model, or generic administration surface.

## Cognito trust boundary

Deployed configuration identifies one regional Cognito User Pool issuer, its exactly derived JWKS
URL, one exact UserInfo path, allowed clients, one resource audience, and exact custom scopes. The
signature algorithm is fixed in code to RS256. Key rotation uses an atomically replaced immutable
JWKS snapshot with single-flight refresh, bounded negative caching, and a finite stale-if-error
window. Malformed refreshes never replace usable key material.

UserInfo is invoked only after local token verification and `openid` scope enforcement. Its exact,
case-sensitive `sub` must match the verified token. No token, JWK, raw claim document, or UserInfo
response is persisted. A generated-key HTTP fixture exists only in test code and the packed smoke
harness; it is absent from the runtime image and forbidden by deployed URL validation.

## Infrastructure boundary

The repository owns application source, schema migrations, tests, a disposable local Compose path,
and a production image definition. `platform-infrastructure` owns AWS/Cognito, Google, DNS,
certificates, network exposure, production PostgreSQL provisioning and roles, backups/restores,
Nginx, deployment, and runtime secret delivery. No production cloud resource is created here.
