# Identity data model

PostgreSQL is authoritative and all tables live in schema `identity`.

## `users`

`id` is an application-generated UUIDv4. Status is `active`, `disabled`, or `deleted`; the database
requires `deleted_at` exactly when status is deleted. Creation and update timestamps use
`timestamptz`.

## `provider_identities`

Each row maps one exact, case-sensitive `(issuer, subject)` pair to one user. Issuer is bounded to
2048 code points and opaque subject to 255. Subject is never parsed as UUID, normalized, or
lowercased. The pair is unique and `user_id` is indexed. Authentication and claim-sync timestamps
record observation state; raw tokens and claim documents are never stored.

Email is deliberately absent. Equal emails do not link or merge accounts. Status changes and any
future scrubbing are audited operator concerns; the runtime role cannot update `users` or delete
rows.

## `profiles`

The user UUID is both primary key and restricted foreign key. Provider-owned fields are email,
email-verification state, display name, and avatar URL. `display_name_override` is the only
user-owned field. The effective name is the override when non-null, otherwise the provider name.

Names are normalized to Unicode NFC, trimmed, checked for control/line-break characters, and
bounded to 100 Unicode code points at the service boundary. Empty provider names become null;
empty local overrides are rejected. Provider email is preserved only as non-unique profile data.
Provider email is either null with verification false, or nonempty and at most 320 code points;
both the service boundary and database enforce that state. Avatar values are stored only when they
are credential-free HTTPS URLs no longer than 2048
characters; invalid snapshots consistently store null and content is never fetched.

`version` begins at 1 and increments only when an effective profile field changes. Local updates
require an expected version in an atomic update condition. Provider synchronization never overwrites
the local override.

Foreign-key deletion is restricted. The future audited deletion workflow will scrub PII and retain
a minimal non-reusable tombstone; that workflow is not currently provided and has no runtime grant.
