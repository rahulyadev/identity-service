# Security boundaries

## Implemented

- Strict environment parsing; development, staging, and production share deployed boundaries.
- Required secret-wrapped PostgreSQL URL with log/representation redaction. Deployed environments
  require one authority TCP destination and exactly one `sslmode=verify-full`; query destination,
  service-file, multi-host, and Unix-domain socket routing are rejected without DNS lookup.
- Strict exact/wildcard host allowlisting and bounded proxy CIDR trust; malformed/duplicate Host
  values are rejected and forwarding headers from untrusted peers are removed.
- A 16 KiB default request-body bound enforced over actual streamed bytes; a partial body followed
  by disconnect never reaches downstream request handling.
- Canonical UUIDv4 correlation IDs generated for missing or invalid input.
- `nosniff`, no-referrer, restrictive CSP, frame denial, and production HSTS headers.
- Generic `application/problem+json` failures with the stable public `code` field and without
  exception, SQL, host, path, or credential details.
- One root-controlled application/Uvicorn logging pipeline with centralized redaction, deployed
  JSON formatting, disabled Uvicorn access logging, and fixed, low-cardinality metric labels.
- Non-root container, dropped capabilities, no-new-privileges, read-only root support, and one
  application process.
- Packed raw-HTTP checks reject ambiguous request framing without executing appended requests;
  production edge/proxy framing consistency remains an infrastructure integration requirement.
- Separate local migrator and runtime roles; runtime lacks DELETE, users UPDATE, identity-mapping
  mutation, schema creation, and version-table write. Mutable provider timestamps and profile
  fields have column-level UPDATE grants only.
- Fixed-RS256 Cognito access-token verification with strict header shape, signature, exact issuer,
  access-token `token_use`, allowed client, resource audience, exact scope, time, and opaque-subject
  checks. Unsafe JWT JSON depth and decoder type/numeric/recursion failures map to bounded typed
  outcomes. Untrusted JWK-location headers are rejected rather than followed.
- Bounded, thread-safe JWKS caching with immutable snapshots, exception-safe single-flight refresh,
  fresh-snapshot-bound exact-key negative caching, rate-limited rotation discovery, atomic
  replacement, and a finite stale-if-error limit. Upstream freshness expiry invalidates negative
  results; one successful snapshot is authoritative for requested-key absence; retry suppression
  follows an actual failure.
- Strict public-JWK validation requires an actual RSA key size of at least 2048 bits and rejects
  contradictory operation metadata and private RSA fields. Unknown JWK Set members are ignored,
  while every key in the bounded `keys` array remains subject to the complete policy.
- A no-proxy, no-redirect upstream client rejects all provider cookie storage and transmission,
  checks remaining capacity before retaining streamed response bytes, and applies separate
  timeouts. The UserInfo adapter requires `openid`, exact case-sensitive subject binding, valid
  UTF-8 and bounded JSON depth, rejects non-finite and integer-limit JSON, bounds decimal
  `Retry-After`, and rejects Unicode control characters in profile claims. JWKS cache freshness
  parsing bounds `Cache-Control` numeric input and never exceeds the configured maximum.
- Verified-token `repr` and `str` output are redacted even if an object is logged accidentally.

The metrics endpoint is unauthenticated and must be restricted by infrastructure. There is no CORS
middleware and direct browser access is unsupported.

## Revocation and synchronization boundary

Offline signature validation does not prove current revocation state. A correctly signed access
token may remain locally valid until expiration after token revocation or global sign-out. During
profile synchronization, Cognito UserInfo supplies a stronger current-state signal because it can
reject expired, revoked, disabled, deleted, or globally signed-out users. A rejection, subject
mismatch, malformed response, timeout, or outage creates or updates no identity data.

Raw bearer tokens, authorization and cookie headers, claims, email, subjects, user IDs, issuer and
UserInfo URLs, client IDs, key IDs, provider bodies, and private keys are prohibited from logs and
metric labels. Metrics use only enumerated outcomes and one-hot cache states.

The fake provider generates ephemeral RSA keys in memory and serves only JWKS and UserInfo to unit,
integration, security, and packed-container tests. It is not copied into the runtime image and no
deployed configuration can select its HTTP/loopback endpoints.

## Not implemented

There is no authenticated HTTP profile endpoint, Google token validation, OAuth authorization code
flow, PKCE, state, nonce, callback, refresh, logout, cookie, session, `/v1/me`, account linking,
username and password, public deletion/export, or production authentication bypass/mock.

No token, authorization code, provider claim document, password, browser session, business role, or
permission is persisted. Logs omit authorization/cookie headers, tokens, provider identifiers,
email, names, avatars, and user IDs.

AWS/Cognito, Google, DNS, certificates, production databases/roles, backups, Nginx, and deployment
belong to `platform-infrastructure`. This repository performs no cloud administration.

The repository generates a CycloneDX inventory of the locked Python runtime dependencies. That
inventory excludes development-only packages and does not represent container or operating-system
packages; an image-level SBOM remains an infrastructure/release concern.
