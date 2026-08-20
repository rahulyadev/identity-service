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

The metrics endpoint is unauthenticated and must be restricted by infrastructure. There is no CORS
middleware and direct browser access is unsupported.

## Not implemented

There is no Cognito JWT/JWKS validation, Google token validation, OAuth authorization code flow,
PKCE, state, nonce, callback, refresh, logout, cookie, session, `/v1/me`, account linking, username
and password, public deletion/export, or authentication bypass/mock. Adding an HTTP profile surface
before token validation would cross this boundary.

No token, authorization code, provider claim document, password, browser session, business role, or
permission is persisted. Logs omit authorization/cookie headers, tokens, provider identifiers,
email, names, avatars, and user IDs.

AWS/Cognito, Google, DNS, certificates, production databases/roles, backups, Nginx, and deployment
belong to `platform-infrastructure`. This repository performs no cloud administration.

The repository generates a CycloneDX inventory of the locked Python runtime dependencies. That
inventory excludes development-only packages and does not represent container or operating-system
packages; an image-level SBOM remains an infrastructure/release concern.
