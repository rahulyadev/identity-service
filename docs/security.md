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
- The `/v1/me` adapter authenticates and authorizes before route-specific validation, requires exact
  UserInfo subject binding for synchronization, and keeps synchronous provider/database work off the
  event loop. It exposes only the stable UUID and minimal effective profile representation.
- Profile writes use a strict strong ETag, duplicate-sensitive header and JSON parsing, one allowed
  merge-patch member, and atomic optimistic versioning. Every exact profile-path response uses
  `no-store`; fixed Bearer challenges and bounded `Retry-After`/`Allow` values are the only preserved
  failure headers. No CORS middleware is enabled.
- The standalone reference BFF generates independent 256-bit state, nonce, and transaction IDs plus
  a longer RFC 7636 verifier. Only the S256 challenge crosses the browser redirect boundary.
- BFF authorization records use a validated application/environment namespace, state-derived digest
  keys, atomic create/consume operations, fixed expiry, strict bounded UTF-8 JSON, and fail-closed
  Redis handling. Consumed malformed records remain consumed.
- BFF local return targets reject absolute, authority, encoded-authority, fragment, backslash,
  control, traversal, duplicate-query, invalid-encoding, oversized, and noncanonical forms.
- Every BFF response is `no-store`, no-referrer, frame-denied, `nosniff`, and restrictive-CSP; host
  and request-ID inputs are bounded, no CORS or cookie is enabled, and logs use a redacting pipeline.

The metrics endpoint is unauthenticated and must be restricted by infrastructure. There is no CORS
middleware and direct browser access is unsupported.

## Image release boundary

The production image workflow has no automatic trigger or user-supplied input. It validates the
exact protected `main` source in a job without an environment or OIDC permission. Only after that
job succeeds can the `production` environment authorize a separate release job with
`contents: read`, `id-token: write`, and `attestations: write`. AWS access uses one short-lived OIDC
role for the exact account, region, registry, and two image repositories; long-lived AWS secrets,
inherited secrets, self-hosted runners, and broad repository permissions are excluded.

Both final ARM64 images use the same digest-pinned official Python multi-architecture base. Both
must build before the first push. Published tags are unique to the full source SHA and workflow
attempt, while every usable output is digest-qualified. BuildKit attaches an image SBOM and maximum
provenance, and GitHub provenance is bound to each action-provided digest. Only a bounded manifest
with non-secret release identity and attestation status is retained.

A failure after one push leaves an immutable, non-deployable partial digest. The workflow neither
deletes nor overwrites it and emits no deployment signal. It has no SSM, EC2, Secrets Manager,
Cognito, DNS, migration, runtime, verification, rollback, or traffic operation. Image scanning and
deployment require an independent digest-specific infrastructure decision.

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

## Browser logout boundary

The Identity service has no browser OAuth behavior. The standalone BFF alone owns callback,
server-side session, refresh, profile proxy, and logout behavior. Logout validates exact-origin,
session-bound CSRF metadata before any mutation, then atomically deletes the exact Redis session.
It makes one bounded best-effort confidential Cognito `/oauth2/revoke` call only after deletion and
navigates the browser to Cognito `/logout` with only the client identifier and derived signed-out
URI. The signed-out route clears both BFF cookies without consulting Redis or a provider.

Cognito logout ends the Cognito managed-login session; it does not sign the user out of Google or
another social/OIDC provider. A subsequent authorization can therefore reuse an active upstream
provider session. The slice adds no global sign-out, provider-specific logout, account linking,
username/password flow, or public deletion/export API.

No token, authorization code, provider claim document, password, browser session, business role, or
permission is persisted. Logs omit authorization/cookie headers, tokens, provider identifiers,
email, names, avatars, and user IDs.

AWS/Cognito, Google, DNS, certificates, production databases/roles, backups, Nginx, and deployment
belong to `platform-infrastructure`. This repository performs no cloud administration.

The repository generates a CycloneDX inventory of the locked Python runtime dependencies. That
inventory excludes development-only packages and does not represent container or operating-system
packages; an image-level SBOM remains an infrastructure/release concern.

## Image inventory and vulnerability gates

Release signatures and provenance establish artifact/source binding, not absence of vulnerabilities.
Python dependency audits cover the locked Python distributions, not Debian libraries or all code
bundled in wheels. Image inventory, vulnerability classification and deployment authorization are
separate requirements. A reported zero with missing OS package metadata is incomplete coverage,
not a clean scan.

The API and BFF preserve authentic DPKG status, ownership and version records even where runtime
package-manager executables are removed. Executable packed checks reject empty, truncated,
uncontrolled or incomplete metadata and compare retained core shared-library bytes with the
package-owned checksum records. DPKG's MD5 records serve file-to-package reconciliation, not image
authenticity; immutable SHA-256 image digests and signed release provenance provide that binding.
SPDX OS identities, versions and architectures must reconcile with the actual packed inventory.
See [container operation](operations.md#container-operation) for the exact base/source/architecture
pins and the deliberate runtime-patch versus validation-toolchain distinction.

Keep complete scanner findings, including unfixed and unknown entries, together with scanner
identity, vulnerability-database build time/checksum, source image digest and vendor advisories.
Classify each finding using the installed binary/source package and Debian's backported version,
not upstream version ordering alone. A generic severity does not establish application
exploitability; unused-by-design code is not by itself proof of absence or non-applicability.
Vendor-unfixed residuals remain visible for explicit risk review. Neither successful signing,
passing Python audits nor restored SBOM coverage independently authorizes runtime deployment.

Both runtime images install only the official Bookworm-security `libpcre2-8-0`
`10.42-1+deb12u1` package over the pinned base's `10.42-1`. Architecture-specific SHA-256
checks bind the downloads to reviewed Debian InRelease/Packages metadata authenticated with
the base's Debian archive keyring. Unsupported architectures, changed download bytes and failed
package transactions stop the build. DPKG performs the installation and library-cache trigger;
its authentic status, ownership and checksum records remain. Packed checks require the reviewed
version and reconcile PCRE2 library bytes with package metadata alongside the other core libraries.
The full Dockerfile construction contract still rejects unreviewed additions or inventory edits.

This backport addresses [CVE-2026-86145](https://security-tracker.debian.org/tracker/CVE-2026-86145)
in recursive DFA matching. It does not establish remediation of other image findings or transfer
any vulnerability acceptance to another digest. A local candidate scan is distinct from a released
image's ECR scan, and neither constitutes authorization to publish or deploy.
