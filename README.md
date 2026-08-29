# identity-service

Identity service to store user data. The service provides a PostgreSQL identity model, a
concurrency-safe internal identity/profile service, strict Cognito access-token verification, a
bounded JWKS cache, a subject-bound UserInfo adapter, an authenticated profile HTTP API,
operational endpoints, migrations, observability, local containers, and automated checks.

The separately packaged `examples/reference_bff` application demonstrates browser login,
confidential callback exchange, independent Cognito token validation, Identity bootstrap, and an
opaque Redis-backed host session with demand-driven refresh, exact profile reads, and a
CSRF-protected conditional profile update and logout. It is not an Identity service import or
runtime dependency, and it listens independently on local port 8081.

The Identity service itself does not provide Google token validation or browser sessions. Its
Bearer-authenticated profile API remains server-to-server; the reference BFF owns the browser
callback and cookie boundary. Unsafe methods other than the bounded profile PATCH and logout,
public refresh/session introspection, and real-provider integration remain outside the current
reference slice.

## Current contract

- Every local user has an application-generated UUIDv4 that remains stable across provider profile
  changes.
- Provider identities resolve only by the exact, case-sensitive `(issuer, subject)` pair. Subjects
  are opaque text; email is profile data and is never an identity key.
- PostgreSQL is authoritative. The Identity service does not use Redis; the standalone reference
  BFF uses Redis only for disposable login transactions and opaque server-side sessions.
- Provider-owned profile fields are replaced by the latest supplied internal snapshot; omitted
  optional fields are cleared. A user-owned display-name override is preserved.
- `PUT /v1/me` initializes or synchronizes the exact authenticated identity through UserInfo.
- `GET /v1/me` reads only the local profile. `PATCH /v1/me` conditionally updates only the
  display-name override using a strong profile-version ETag.
- Disabled and deleted users are unavailable. There is no public deletion or export API or
  deletion/scrubbing workflow.

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

`requirements.lock` is the Identity production dependency set.
`examples/reference_bff/requirements.lock` is the separate BFF production dependency set.
`requirements-dev.lock` contains the combined exact validation toolchain. Regenerate all three
with `make lock` and review the diff.

## Local PostgreSQL and application

The Compose credentials are fixed, obvious local-only values. Never reuse them outside the
disposable local environment.

```sh
make db-up
make migrate
make app-up
curl --fail http://localhost:8080/health/live
```

Readiness also needs a usable JWKS snapshot. Supply the documented local/test Cognito fixture URLs
when exercising the app manually; `make docker-smoke` creates and removes an ephemeral fixture
automatically and never calls a real identity provider.

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
make test-bff-unit     run BFF primitive and configuration tests
make test-bff-contract run BFF HTTP contract tests
make test-bff-security run BFF security and redaction tests
make test-bff-redis    run one-time-store tests against disposable Redis
make test-integration  run PostgreSQL service tests
make test-migrations   run disposable upgrade/downgrade/re-upgrade tests
make coverage          enforce branch-aware 90% overall coverage
make coverage-bff      enforce independent BFF branch-aware 90% coverage
make openapi           regenerate openapi/openapi.json
make openapi-check     compare generated OpenAPI with the committed artifact
make sbom              generate the runtime dependency CycloneDX JSON under .cache/security
make sbom-check        validate the SBOM component set against requirements.lock
make bff-sbom-check    validate the separate BFF runtime SBOM and lock
make security          dependency audit, SBOM, documentation, secret, and Bandit checks
make release-workflow-check verify the fixed production image-release contract
make docker-build      build the production runtime image
make docker-smoke      test the packed image, outage recovery, hardening, and shutdown
make docker-smoke-bff  test the packed BFF with disposable Redis and outage recovery
make validate-offline  run checks that need no PostgreSQL or application container
make validate-local    run the complete local validation sequence
make validate          alias the complete local validation sequence
```

Database test commands require the three `TEST_*_DATABASE_URL` values used by the Makefile. They
fail rather than substituting SQLite or skipping required tests. `make validate-offline` makes no
release-readiness claim. Both `make validate-local` and `make validate` require Docker immediately,
then run PostgreSQL migrations, disposable Redis integration, every test class, independent branch
coverage for both packages, both production-image builds, and both packed-image smoke checks;
neither can succeed after only the offline subset.

## Runtime dependency SBOM

`make sbom-check` generates and semantically validates a CycloneDX JSON inventory from the exact
packages in `requirements.lock`. Packages that exist only in `requirements-dev.lock` are excluded,
and the check rejects stale components, credentials, private repository references, and local
workspace paths. Normal output is written beneath the ignored `.cache/security` directory.

`make bff-sbom-check` applies the same semantic and secret-safe checks to the exact packages in the
standalone BFF runtime lock. Neither runtime inventory may acquire packages from the other runtime
merely because the combined development environment contains both.

## Reference BFF surface

The BFF exposes process liveness, Redis/JWKS-backed readiness, `GET /auth/login`,
`GET /auth/callback`, cookie-authenticated `GET`/`PATCH /api/me`, `POST /auth/logout`, and
`GET /auth/signed-out`. Login accepts one optional canonical local `return_to`, stores a
fixed-lifetime one-time record before redirecting, and includes the
exact Identity resource plus scope, state, nonce, and PKCE S256 bindings. The independent
transaction ID remains in the bounded server-side record and appears in the browser only as a
short-lived opaque `__Host-oauth` binding.
Callback strictly consumes that record, requires a constant-time match to the initiating browser
before denial or exchange, validates both Cognito tokens, completes `PUT /v1/me`, stores a
versioned expiring Redis session, clears the binding, sets one opaque host-only `__Host-session`
cookie, and redirects locally with `303`.

The profile read rejects query strings, bodies, browser bearer tokens, and ambiguous raw Cookie
fields. It atomically touches the idle TTL without extending the absolute lifetime, rotates a
complete Cognito token set at the refresh boundary through a Redis-backed per-version single
flight, and calls only Identity `GET /v1/me` with the server-held access token. A success contains
only the validated eight-field profile, matching strong ETag, security headers, the unchanged
session ID, and the independent synchronizer token in exactly one `X-CSRF-Token` response header.
Fixed 401/503 failures never disclose upstream bodies or session material.

The conditional profile update authenticates the same opaque session, then requires an exact
`Origin` equal to `BFF_ORIGIN`, one constant-time matching canonical `X-CSRF-Token`, optional
`Sec-Fetch-Site: same-origin`, one strong `If-Match: "vN"`, merge-patch JSON, and an exact bounded
`display_name` member. Only the BFF's normalized one-member representation, server-held bearer,
and validated precondition reach Identity `PATCH /v1/me`. A success returns the strict profile,
matching ETag, the same CSRF token header, and the same opaque session ID; stale writes are fixed
`412 profile_conflict`. CSRF denials occur before refresh, touch, upstream access, or Redis writes.

Logout applies the same exact session-bound CSRF and origin checks before state change, then
atomically deletes only the loaded Redis session. Only after local deletion does the BFF make one
bounded, best-effort confidential Cognito revocation request. Revocation failure cannot restore the
session or change the `303` browser navigation to Cognito `/logout`, whose only query fields are the
configured client identifier and the derived `${BFF_ORIGIN}/auth/signed-out` URI. That signed-out
route clears both BFF cookies and returns `303 /` without Redis or provider access. Cognito logout
does not sign the user out of Google or another social/OIDC provider, so a later login can reuse an
active upstream provider session.

OAuth transport necessarily carries state and nonce only on the provider authorization request and
code/state or error/state only on the callback request. None of the transaction ID, state, nonce,
code, or error values propagate into the final local redirect, response body, session cookie, other
browser or application storage, logs, exceptions, representations, metrics, or review evidence.
The client secret, Redis credentials, verifier, provider subjects, OAuth tokens, provider bodies,
and session records remain outside every public surface. The browser-readable synchronizer token
is unrelated to OAuth material, persists only inside its server-side session, and appears publicly
only in successful same-origin profile response headers; no CORS header permits another origin to
read it.
Neither the login/callback binding nor `SameSite=Lax` replaces the exact CSRF validation on the
profile PATCH or logout. Other unsafe methods, public refresh/session introspection, global
sign-out, provider-specific logout, real provider access, and deployment remain absent. See
[the standalone example](examples/reference_bff/README.md) for its configuration boundary.

This Python runtime SBOM does not inventory operating-system or container-image packages.
Infrastructure or release automation may later combine it with an independently generated
image-level SBOM.

## Production image release

The manual `release-production.yml` workflow is the only production image publisher in this
repository. It accepts no inputs and runs only for the exact `main` commit in
`rahulyadev/identity-service`. A separate validation job runs the complete `make validate` gate
before the `production` environment or AWS OIDC permission is available to the release job.

The release job builds both `linux/arm64` runtime targets before authenticating to the exact
`ap-south-1` ECR registry. It uses a short-lived environment-bound role, fixed API and BFF
repository mappings, a full-source-SHA/run-ID/attempt tag, BuildKit SBOMs, maximum provenance, and
digest-bound attestations. Its uploaded JSON manifest contains only the source/run identity,
platform, two digest-qualified image references, and attestation status. A partial push is
explicitly non-deployable and is never deleted or overwritten by the workflow.

The shared `python:3.14.4-slim-bookworm` base is pinned by the same official multi-architecture
index digest in both Dockerfiles. `make release-workflow-check` parses the workflow without a shell
and rejects trigger, trust, permission, runner, image mapping, tag, attestation, logging, or
deployment widening. Image publication does not deploy either application, run SSM, migrate a
database, alter runtime infrastructure, or activate production traffic.

## Operational endpoints

| Method | Path | Behavior |
| --- | --- | --- |
| `GET` | `/health/live` | Process/application liveness only; never queries PostgreSQL. |
| `GET` | `/health/ready` | `200` only when PostgreSQL is reachable, the one stored Alembic revision equals the packaged head, and the bounded Cognito JWKS cache is usable; otherwise safe `503`. |
| `GET` | `/metrics` | Prometheus metrics when `METRICS_ENABLED=true`; intended for infrastructure-restricted access. |
| `GET` | `/openapi.json` | Generated OpenAPI document. |
| `PUT` | `/v1/me` | Initialize or synchronize the authenticated identity; requires `profile.write` and `openid`. |
| `GET` | `/v1/me` | Read the authenticated local profile; requires `profile.read` and never calls UserInfo. |
| `PATCH` | `/v1/me` | Conditionally set or clear `display_name`; requires `profile.write`, merge-patch JSON, and `If-Match: "vN"`. |

Swagger UI and ReDoc may be enabled only in local/test environments and are forbidden in deployed
development, staging, and production. Their local HTML uses the default external static assets and
therefore omits the API-only CSP; JSON, metrics, problem, and operational responses retain the
restrictive policy. `/openapi.json` is the stable machine-readable contract. There is deliberately
no CORS middleware because direct application-browser access is unsupported.

Every failure body uses `application/problem+json` and the public fields `type`, `title`, `status`,
`detail`, `request_id`, and `code`. Stable `code` examples include `not_ready`, `body_too_large`,
and `internal_error`. The internal structured-log field remains `error_code`; it is not part of the
HTTP contract.

Successful profile representations contain exactly `user_id`, `email`, `email_verified`,
`display_name`, `avatar_url`, `version`, `created_at`, and `updated_at`. Every profile success has
`ETag: "vN"`, and every response on the exact `/v1/me` path has `Cache-Control: no-store`.
Authentication and scope failures use fixed Bearer challenges. Missing, malformed, and stale PATCH
preconditions are distinct `428`, `400`, and `412` problems. The API has no CORS middleware.

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
| `COGNITO_ISSUER` | exact User Pool issuer; deployed environments require one regional HTTPS Cognito issuer and pool path |
| `COGNITO_JWKS_URL` | exactly issuer plus `/.well-known/jwks.json`; redirects are disabled |
| `COGNITO_USERINFO_URL` | credential-free URL with exact `/oauth2/userInfo` path; HTTPS when deployed |
| `COGNITO_ALLOWED_CLIENT_IDS` | JSON array of 1–16 unique bounded client IDs |
| `OAUTH_RESOURCE` | exact access-token audience/resource (`identity-service://api` for local tests) |
| `OAUTH_PROFILE_READ_SCOPE` / `OAUTH_PROFILE_WRITE_SCOPE` | distinct exact scopes namespaced beneath the resource |
| `JWT_CLOCK_SKEW_SECONDS` / `JWT_MAX_TOKEN_BYTES` | `60` / `16384`; both strictly bounded |
| `JWKS_CACHE_MAX_AGE_SECONDS` / `JWKS_STALE_IF_ERROR_SECONDS` | `300` / `1800`; stale fallback has a hard bound |
| `JWKS_REFRESH_MIN_INTERVAL_SECONDS` / `JWKS_NEGATIVE_KID_CACHE_SECONDS` | `10` / `10`; limits refresh storms |
| `JWKS_MAX_KEYS` | `16` |
| `UPSTREAM_*_TIMEOUT_SECONDS` | connect `2`, read `3`, write `3`, pool `2`; independent bounds |
| `UPSTREAM_MAX_RESPONSE_BYTES` | `65536` |
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

Development, staging, and production require HTTPS provider URLs, reject credentials, query and
fragment components, reject loopback endpoints, and require the JWKS URL to derive exactly from a
regional Cognito User Pool issuer. The only HTTP/loopback relaxation is local/test fixture use. The
shared upstream client ignores proxy environment variables, follows no redirects, rejects provider
cookie storage and transmission, uses bounded timeouts, and checks the remaining response allowance
before retaining each streamed chunk. It sends bearer authorization only to the configured
UserInfo destination.

The verifier fixes the algorithm to RS256, requires at least 2048-bit RSA verification keys, and
validates the signature, exact issuer, access-token `token_use`, allowed `client_id`, resource
audience, exact required scopes, bounded time claims, and opaque subject. Bounded structural
pre-validation rejects unsafe JWT JSON depth without using unverified claims for authorization;
decoder type, numeric, and recursion failures become redacted typed token outcomes. The first
lookup after the effective freshness deadline triggers one
single-flight refresh even when an upstream `max-age` is shorter than the retry interval. The
refresh interval suppresses retries only after an actual failed refresh and bounds hostile
unknown-key storms; degraded stale use never begins merely because a successful fetch was recent.
A previously loaded snapshot may be used after failure only through the configured stale-if-error
hard limit. Exact negative-key results are bound to the fresh snapshot that proved absence, and one
successful refresh that omits a requested key is authoritative without a second provider request.
Public JWKS keys reject contradictory `key_ops`, private RSA fields, and weak RSA material while
standards-valid additional JWK Set members are ignored. JWKS and UserInfo JSON reject non-finite
numbers, numeric conversion-limit input, malformed encoding, and excessive nesting. Oversized
`Cache-Control` values use a conservative one-second freshness policy; invalid directives are
ignored and the lowest valid bounded `max-age` wins. UserInfo requires `openid`, validates a
matching case-sensitive `sub`, accepts only a short decimal `Retry-After` of at most 300 seconds,
rejects Unicode control characters, and parses only a bounded profile claim set before existing
transactional identity synchronization. Verified-token string representations are always redacted.

Offline signature verification cannot provide instantaneous revocation awareness: a revoked or
globally signed-out token can remain locally verifiable until its expiration. Cognito UserInfo can
reject expired, revoked, disabled, deleted, or globally signed-out users during synchronization,
providing a stronger current-state check at that point. Raw tokens, claims, subjects, email,
provider responses, URLs, client IDs, and key IDs are excluded from logs and metric labels.

## Ownership boundary

This repository creates no production cloud resources. AWS/Cognito, Google configuration, DNS,
certificates, production databases, backups, restore execution, Nginx, and deployment belong to
`platform-infrastructure`. This service defines the database schema and restore compatibility;
platform owners operate and test backups and restores. CI requires no cloud or repository secrets
and performs no deployment.

GitHub Actions use current official major release tags (`actions/checkout@v7` and
`actions/setup-python@v7`). Major tags permit upstream security maintenance while keeping breaking
changes reviewable.
