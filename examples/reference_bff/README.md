# Reference BFF

This standalone example completes the browser-facing authorization-code callback through session
issuance and one cookie-authenticated profile read. It owns short-lived Redis authorization
transactions, validates Cognito tokens independently, bootstraps and reads the Identity profile,
rotates refresh tokens behind a per-session Redis single flight, and stores OAuth tokens only in an
opaque server-side session. It does not import or run the Identity service.

The public surface is deliberately small:

- `GET /health/live` checks only the BFF process.
- `GET /health/ready` proves transaction consume, session load/touch/CAS, refresh-lock ownership,
  cleanup, and a usable bounded JWKS snapshot. Its short-lived probes leave no key after success.
- `GET /auth/login` validates an optional local `return_to`, persists a one-time transaction, and
  returns a resource-bound provider redirect using state, nonce, and PKCE S256. Its independent
  transaction ID remains in the bounded server-side record and binds the initiating browser only
  through a short-lived opaque `__Host-oauth` cookie.
- `GET /auth/callback` strictly consumes one success or denial callback. A success exchanges the
  code only after the consumed transaction matches the browser binding, validates the ID/access
  tokens, calls `PUT /v1/me`, creates one Redis session, sets `__Host-session`, clears the login
  binding, and redirects with `303` to the canonical local target.
- `GET /api/me` accepts no query, body, or browser bearer token. It requires exactly one canonical
  `__Host-session` value from duplicate-safe raw Cookie fields, uses only the server-held access
  token for Identity `GET /v1/me`, strictly validates the eight-field profile and strong ETag, and
  renews the same opaque cookie without extending the absolute session deadline.

The browser receives no OAuth token or identity value. The cookie is an independent 256-bit opaque
identifier with `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, no `Domain`, and a bounded
`Max-Age`. Redis records are strictly parsed, versioned, use one-way derived keys, and expire no
later than the 12-hour idle or seven-day absolute limit. Atomic compare-and-set touch and
replacement prevent stale overwrites, deleted-session resurrection, and absolute-lifetime
extension. Redis loss causes reauthentication; it never loses the authoritative Identity profile.

Unsafe application methods, public refresh/session introspection, CSRF tokens, logout, revocation,
and `/auth/signed-out` are intentionally absent. Cognito logout and Google logout semantics are
therefore not implemented by this slice. `SameSite=Lax` and the login/callback browser binding are
not the deferred CSRF protection required before any future unsafe cookie-authenticated method can
exist.

Refresh is internal and demand-driven. Outside the refresh window, reads use the current access
token and atomically touch the idle TTL. At the boundary, a digest-keyed Redis lease with an
independent 256-bit owner marker admits one token request for the current `refresh_version`; other
readers wait boundedly for a strictly newer version. The complete rotated ID, access, and refresh
set is independently verified before one CAS replacement. A temporary refresh/JWKS failure may
permit one read only while the current access token remains valid; after expiry it returns fixed
`503 session_unavailable` without clearing the otherwise valid session. Definitive refresh or
Identity rejection atomically invalidates the exact session and returns fixed
`401 session_required` with cookie clearing. Unsafe Identity responses return fixed
`503 identity_unavailable` without exposing their body.

OAuth transport necessarily places state and nonce only on the outbound provider authorization
request, then code/state or error/state only on the inbound callback request. None of the
transaction ID, state, nonce, code, or error values continue into the final local `303`, response
body, session cookie, other browser or application storage, logs, exceptions, representations,
metrics, or review evidence.

The packed runtime removes Python and operating-system package-manager tooling after its locked
dependencies are installed. Packed-image validation proves that boundary along with non-root,
read-only, capability-dropped operation.

## Configuration boundary

Configuration is supplied only through environment variables. `BFF_CLIENT_SECRET` and `REDIS_URL`
are secret fields and are redacted from representations and validation errors. The regional
Cognito issuer and exact issuer JWKS URL are separate from the managed-login authorization/token
authority. The Identity API is configured as an origin and callback is derived only from
`BFF_ORIGIN`. Deployed environments require HTTPS upstreams, a regional Cognito issuer,
`rediss://`, explicit hosts, restrictive proxy networks, JSON logging, and disabled interactive
documentation.

The callback URI is derived as `${BFF_ORIGIN}/auth/callback`; it is not independently configurable.
The default transaction lifetime is 300 seconds and may not exceed 600 seconds. Requested scopes
must include `openid`, `identity-service://api/profile.read`, and
`identity-service://api/profile.write`; login adds the exact `identity-service://api` resource
indicator. ID and access tokens are independently restricted to RS256, the exact issuer, client,
resource, nonce, subjects, times, scopes, and bounded JWKS policy. An ID-token `at_hash`, when
present, must match the exact access token.

## Local execution

The repository Compose file supplies fixed disposable local credentials and Redis with persistence
disabled. It binds the BFF on loopback port 8081 and Redis on a loopback-only test port. Packed
validation starts an in-memory synthetic token/JWKS/Identity fixture, exercises success, denial,
cross-browser rejection, replay, 50-way refresh-boundary concurrency, stable session-cookie renewal,
CAS/non-resurrection/lock cleanup, provider/Identity/Redis outages and recovery, inspects the
server-side session, and then removes the disposable stack. Production secrets and real provider
access are not needed.
