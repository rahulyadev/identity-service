# Reference BFF

This standalone example is the browser-facing start of an OAuth authorization-code flow. It owns
short-lived Redis authorization transactions and redirects a browser to the configured provider.
It does not import or run the Identity service.

The public surface is deliberately small:

- `GET /health/live` checks only the BFF process.
- `GET /health/ready` performs a short-lived `SET NX EX` plus `GETDEL` capability probe under a
  dedicated readiness namespace and leaves no key after success.
- `GET /auth/login` validates an optional local `return_to`, persists a one-time transaction, and
  returns a temporary provider redirect using state, nonce, and PKCE S256.

Callback handling, code exchange, token validation, profile bootstrap, application sessions,
cookies, CSRF-protected routes, refresh, and logout are intentionally absent. Redis loss restarts a
login attempt; Redis never contains durable identity data.

The packed runtime removes Python and operating-system package-manager tooling after its locked
dependencies are installed. Packed-image validation proves that boundary along with non-root,
read-only, capability-dropped operation.

## Configuration boundary

Configuration is supplied only through environment variables. `BFF_CLIENT_SECRET` and `REDIS_URL`
are secret fields and are redacted from representations and validation errors. Deployed
environments require HTTPS origins/provider endpoints, `rediss://`, explicit hosts, restrictive
proxy networks, JSON logging, and disabled interactive documentation.

The callback URI is derived as `${BFF_ORIGIN}/auth/callback`; it is not independently configurable.
The default transaction lifetime is 300 seconds and may not exceed 600 seconds. Requested scopes
must include `openid`, `identity-service://api/profile.read`, and
`identity-service://api/profile.write`.

## Local execution

The repository Compose file supplies fixed disposable local credentials and Redis with persistence
disabled. It binds the BFF on loopback port 8081 and Redis on a loopback-only test port. Production
secrets and real provider access are not needed for the example validation.
