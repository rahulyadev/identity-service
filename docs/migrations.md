# Migrations

Alembic has one linear head: `0001_initial_identity_schema`. Its version table is
`identity.alembic_version`.

The explicit provisioning decision is that the database and `identity` schema already exist and the
migrator role owns the schema. Migrations create only versioned tables, constraints, and indexes;
they do not create databases, users, production roles, extensions, or infrastructure. Production
role grants remain an infrastructure responsibility. The local initialization script and local
migration helper model those grants only for disposable Compose.

The local runtime role receives explicit rights only after migration: SELECT/INSERT on the three
application tables, column-level UPDATE on provider observation timestamps and mutable profile
fields, and SELECT on `identity.alembic_version`. It receives no DELETE, no users UPDATE, and no
default privilege on future tables or sequences. Future migrations must explicitly add a reviewed
runtime privilege when corresponding service code actually requires it. Status changes and future
scrubbing belong to a separately audited operator workflow, not the application role.

```sh
make db-up
make migrate
make migration-heads
make test-migrations
make migration-drift
```

The application role never runs migrations, and application startup never attempts schema repair.
Readiness requires the stored database revision to equal the sole head packaged in the application.

## Downgrade warning

Downgrading the initial revision to base drops all three identity tables and destroys identity data.
The downgrade test runs only against a freshly named disposable database and then re-upgrades it.
Never use this as an automatic production rollback.

Normal production rollback deploys the previous application image against a backward-compatible,
expanded schema. Contracting or destructive schema work requires a separately reviewed data plan,
backup/restore readiness, and explicit operator action.
