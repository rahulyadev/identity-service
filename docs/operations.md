# Operations

## Health and readiness

`GET /health/live` always checks only the application process. It never touches PostgreSQL.

`GET /health/ready` opens a bounded pooled connection, runs `SELECT 1`, reads the version table, and
requires a usable Cognito JWKS snapshot. It returns `200 {"status":"ready"}` only for the one exact
packaged migration head and fresh or bounded-stale verification keys. Missing, older, newer,
multiple, inaccessible, timed-out, never-loaded, or hard-stale states return a generic `503`
problem without repairing anything or exposing which dependency failed.

Readiness is a normal synchronous FastAPI path operation and is dispatched to a framework worker
thread. A blocked readiness check cannot block the event loop from serving liveness. Future HTTP
endpoints that use this synchronous persistence layer must retain a proper thread-pool boundary.

JWKS refresh is single-flight across readiness and token verification. A fresh snapshot is ready.
The first caller after the effective freshness deadline refreshes even when an upstream `max-age`
is shorter than `JWKS_REFRESH_MIN_INTERVAL_SECONDS`. That interval suppresses repeated failed
refreshes and hostile unknown-key storms; it never overrides an expired successful freshness
deadline. Negative key results expire with the exact fresh snapshot that proved absence, so key
rotation is discoverable immediately after normal freshness ends. A successful refresh that omits
the requested key returns the bounded unknown-key result after that one request. After an actual
refresh failure, the previous snapshot is ready only until the configured stale-if-error hard limit
and reports an internal degraded metric; beyond that limit readiness fails. A valid refresh
recovers without restart, while weak RSA material, malformed encoding, non-finite or conversion-limit
JSON numbers, excessive JSON depth, oversized, redirected, or otherwise invalid responses never
replace the prior snapshot. Unknown top-level JWK Set members are ignored without changing key,
location, algorithm, or lifetime policy. Every refresh exit clears its single-flight state and wakes
waiters. Shutdown closes the HTTP client, rejects publication by an in-flight fetch, and releases
cache waiters.

Only parsed RSA public keys of at least 2048 bits are published, and verified decode independently
enforces PyJWT's minimum-key policy. `Cache-Control` numeric tokens are length-bounded before
conversion; the lowest valid `max-age` can shorten but never extend configured freshness, malformed
directives are ignored, and an oversized complete header receives a conservative one-second
freshness. UserInfo accepts only a one-to-three-digit ASCII `Retry-After` value no greater than 300;
oversized, negative, whitespace-padded, or date-form values provide no retry hint.

Connection, pool-wait, statement, recycle, and graceful-shutdown limits are configured separately.
There is no broad request timeout that cancels a synchronous database operation.

Development, staging, and production accept only a `postgresql+psycopg` URL with one explicit DNS,
IPv4, or bracketed IPv6 authority host, an optional valid authority port, and exactly one
`sslmode=verify-full`. Query destination overrides, PostgreSQL service/service-file routing,
multiple hosts, and Unix-domain sockets are rejected before engine creation. No DNS lookup or
database connection occurs during settings validation. The Unix-socket relaxation is limited to
deliberately configured local/test operation.

## Authenticated profile operations

`PUT /v1/me` verifies `profile.write` and `openid`, calls UserInfo with the same access token, and
atomically initializes or synchronizes the exact issuer/subject identity. `GET /v1/me` verifies
`profile.read` and reads PostgreSQL only. `PATCH /v1/me` verifies `profile.write`, requires
`application/merge-patch+json` plus one strong `If-Match: "vN"`, and atomically changes only the
display-name override. A same-value PATCH is an idempotent no-op; competing requests using one ETag
produce one update and version conflicts for the remaining requests.

All successful responses expose the minimal external representation and a matching strong ETag.
All exact `/v1/me` responses, including authentication, validation, dependency, and method failures,
use `Cache-Control: no-store`. PostgreSQL failures become bounded `database_unavailable` problems;
UserInfo failures do not change identity rows; and UserInfo outages do not prevent ordinary local
reads. Liveness remains dependency-free.

## Metrics and logging

When enabled, `/metrics` publishes request counts/duration/status, readiness, database errors, pool
usage, bootstrap and profile-update outcomes, JWT validation outcomes, JWKS fetch/cache state and
age, and UserInfo outcomes. Labels are restricted to method, route template, status, operation,
fixed outcome, and fixed cache state. Infrastructure must restrict the endpoint.

Deployed development, staging, and production logging is JSON with timestamp, level, logger,
message, service, version, environment, and a bounded event category. Request-completion records
also contain request ID, route template, method, status, duration, outcome, and bounded internal
error code/type. Application and Uvicorn lifecycle/error records share the same root handler and
central redacting filter; Uvicorn access logging is disabled because the application emits its own
bounded completion record. Reconfiguration is idempotent and does not duplicate handlers or
lifecycle events. Bodies and identity/profile values are never logged.

Public HTTP problems use `type`, `title`, `status`, `detail`, `request_id`, and `code`. The internal
log attribute `error_code` is not exposed in problem JSON or OpenAPI.

## Container operation

The image pins Python `3.14.7`, runs UID/GID 10001, writes no bytecode, and needs only an explicitly
mounted writable `/tmp`; the root filesystem can be read-only. It runs one Uvicorn process, disables
Uvicorn proxy-header interpretation, and handles SIGTERM through the configured graceful timeout.
Alembic is never an application entrypoint side effect.

Both dependency and runtime stages of the API and BFF use the official
`python:3.14.7-slim-bookworm@sha256:416f0db2a2b561945630cef9877a7ea0581b27449eb9fd9df42f03e1b74b5b63`
multi-architecture index. Its Linux child manifests are:

- amd64: `sha256:6e9a7d1f48cf0127a5be29b58dba0c7f1b59c118619f011b7a6fca28d00adfd4`.
- arm64/v8: `sha256:4ef8fbc5d4e068625ed1abfb3c83fd937293c9a68e29e344175c7cb291f1365c`.

The [official Docker Python source](https://github.com/docker-library/python/blob/228f71e70a42ba9f9a092321b971031603bb88ff/3.14/slim-bookworm/Dockerfile)
binds this patch release to its build recipe. Local and CI validation retain Python `3.14.4` as
the supported minimum/toolchain; the production image patch is deliberately newer. Packed checks
verify the actual `3.14.7` runtime rather than inferring it from a tag. A base refresh requires
fresh image-level inventory, SBOM, provenance, scans and functional validation for both images.
The release verifier freezes the complete Dockerfiles as well as their base stages, so added
construction commands cannot silently remove, truncate or replace package metadata.

Both images retain the authentic root-controlled `/var/lib/dpkg` database and ownership/checksum
records. Packed validation parses that data without invoking a package manager and reconciles
retained core shared libraries with their package records. Image-level SPDX validation compares
every Debian package identity, version and architecture against the actual database, rejecting
catalog omissions. Removing BFF apt/dpkg executables does not remove this inventory requirement.

The local Compose database is PostgreSQL `18.4-bookworm`. Its credentials and roles are disposable
local examples only. `make docker-smoke` starts the database, migrates explicitly, starts the packed
application, verifies liveness/readiness, database outage and restart recovery, non-root/read-only
operation, dropped capabilities, no-new-privileges, the runtime-tooling boundary, one application
process, bounded JWKS outage/stale/rotation recovery against an ephemeral test-only fixture,
authenticated profile initialization/read/conditional-update behavior, provider and database
outage separation, and bounded SIGTERM shutdown. It removes only its own Compose volume afterward.

The image health script connects directly to loopback without proxy-environment processing, but
sends the canonical Host derived from validated `IDENTITY_ORIGIN`. Public `ALLOWED_HOSTS` therefore
does not need `127.0.0.1`; local Compose accepts `identity.test` for the probe and `localhost` for
documented host access. The probe reads only the exact bounded liveness response and remains
independent of PostgreSQL.

Local/test Swagger UI and ReDoc use FastAPI's configured external static assets. Only their two HTML
routes omit the otherwise blocking API CSP. Interactive docs are rejected in development, staging,
and production, while `/openapi.json` remains available as the stable machine-readable contract.

`make validate-offline` is the no-PostgreSQL subset and does not claim release readiness.
`make validate-local` is the complete gate and fails at one explicit prerequisite check when Docker
is unavailable. `make validate` aliases that complete gate rather than the offline subset.

## Production image publication

Production image publication is an operator-triggered GitHub workflow with no inputs. The workflow
refuses any repository other than `rahulyadev/identity-service`, any event other than
`workflow_dispatch`, and any ref other than `refs/heads/main`. Checkout is fixed to the complete
40-hex dispatch SHA with credential persistence disabled. The validation job has only repository
read permission and completes `make validate` before the environment-scoped release job can obtain
a short-lived OIDC session.

The release job targets only `linux/arm64` and the final `runtime` stage in `Dockerfile` and
`examples/reference_bff/Dockerfile`. It prebuilds both OCI images with SBOM and maximum provenance
before the first registry push, then authenticates only to
`402906459349.dkr.ecr.ap-south-1.amazonaws.com`. The fixed repository mapping is:

```text
Dockerfile                         -> platform-infrastructure-production-identity-api
examples/reference_bff/Dockerfile  -> platform-infrastructure-production-identity-bff
```

Every release tag contains the full source SHA, workflow run ID, and run attempt. The workflow uses
the digests returned by the image builder, creates only digest-qualified references, binds GitHub
provenance to each digest, and uploads one bounded JSON manifest for seven days. Operators must
treat any failed or partial run as non-deployable even when one immutable digest was published.
They must not discover a release later by tag or delete the partial image.

The workflow does not read application secrets, call SSM, configure a host, run migrations, deploy
containers, change DNS or Cognito, inspect traffic, or perform rollback. ECR scanning and a later
digest-specific deployment decision remain separate infrastructure operations. Run
`make release-workflow-check` locally to enforce the static contract; it is also part of
`validate-offline` and the complete validation gate.

## Reference BFF operation

The standalone BFF listens on 8081. Its liveness endpoint is process-only; readiness performs one
bounded Redis operation and recovers after the disposable store returns. Redis persistence is
disabled in the local Compose profile and its test port is bound only to loopback. Losing Redis
invalidates pending login attempts and does not lose durable identity data.

`make test-bff-redis` exercises real atomic creation and consumption, fixed expiry, malformed-record
removal, namespace isolation, pool cleanup, and fifty-way consume concurrency. `make coverage-bff`
enforces an independent branch threshold. `make docker-smoke-bff` builds the separate runtime image,
starts only disposable Redis and the BFF, verifies login initiation and restrictive headers, proves
liveness/readiness separation during an outage and recovery, checks the non-root/read-only/
capability-dropped package boundary, and requires bounded SIGTERM shutdown.

The packed BFF image contains neither Identity source nor development/package-management tooling.
Its provider URL is not contacted by this functionality. Deployed configuration requires HTTPS,
TLS Redis transport, explicit non-loopback destinations, JSON logging, and disabled interactive
documentation.

The packed-image smoke gate sends bounded raw HTTP/1.1 requests directly to Uvicorn/h11 and rejects
ambiguous `Content-Length`, `Transfer-Encoding`, and chunk framing if they produce a successful or
second response. A clean connection must remain healthy after each rejection. Production edge and
proxy deployments must separately verify that every hop applies consistent HTTP framing rules.

## Runtime dependency SBOM

`make sbom` uses the locked `pip-audit` toolchain to generate CycloneDX JSON for every Python
package in `requirements.lock`. `make sbom-check` compares normalized names and versions with that
runtime lock, rejects development-only components, and scans for credentials and local paths. The
normal artifact lives under ignored `.cache/security` output. It does not include base-image or
operating-system packages; release infrastructure may combine it with an image-level inventory.

`make bff-sbom-check` generates and validates the independent BFF inventory from
`examples/reference_bff/requirements.lock`. The combined development lock is used only to prove
that development-only packages do not leak into either runtime inventory.

## CI

CI uses Python 3.14.4, PostgreSQL 18.4, only hash-locked Python dependencies, zero cloud secrets, and
no deployment. It checks installed dependency consistency, formatting, Ruff, strict mypy, every
test class, branch coverage, one migration head, metadata drift, deterministic OpenAPI, dependency
vulnerabilities, the runtime SBOM, public-document hygiene, secrets, static security, the production
image, and a packed-container smoke path. Official GitHub Actions are pinned to reviewed current
major tags.

`httpx2` is the single runtime HTTP stack for JWKS and UserInfo. It is configured with proxy
environment trust disabled, redirects disabled, TLS verification enabled, separate bounded
timeouts, a small connection pool, a response-size limit enforced before each buffer append, a
fixed user agent, and a rejecting cookie policy that stores and sends no provider cookies. Provider
JSON is decoded strictly: non-standard `NaN` and infinity constants and integer-conversion-limit
input become typed malformed-provider outcomes without retaining response content. PyJWT with its
cryptographic backend performs verified RS256 decoding with explicit claim and minimum-key
requirements; no alternate JWT implementation is present.

## Backup and restore

This repository documents schema compatibility and supplies migrations. `platform-infrastructure`
owns production backup scheduling, encryption, retention, restore execution, and restore drills.
Application operators must verify the restored Alembic revision before declaring readiness.

### Exact Debian runtime correction

The runtime stages apply one package-managed Bookworm-security correction: `libpcre2-8-0`
`10.42-1` to `10.42-1+deb12u1`, before the BFF removes package-manager executables.
The reviewed amd64 and ARM64 package hashes are embedded in both Dockerfiles; the fixed URL,
architecture selection, checksum verification and exact before/after version checks fail closed.
There is no general APT upgrade or dependency refresh. The base digest and all Python inputs
and locks remain separate controls; use `make lock-check` to verify them.

Review both actual ARM64 candidates with original SPDX and maximum provenance, all 97 Debian
identities, unchanged Python distributions and authenticated package-file hashes. Only PCRE2's
package version and package-managed contents change; DPKG transaction records and the libc
linker-cache trigger may update generated metadata without upgrading libc. Keep unfiltered
scanner results and database identity. A failed or overdue scan remains recorded even after a
later successful scan; a rescan does not extend an exception or authorize deployment.
