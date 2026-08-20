\set ON_ERROR_STOP on

REVOKE ALL ON DATABASE identity_service FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

CREATE ROLE identity_service_migrator
    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
    PASSWORD 'localmigrator'; -- pragma: allowlist secret (fixed disposable local credential)
CREATE ROLE identity_service_app
    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
    PASSWORD 'localapp'; -- pragma: allowlist secret (fixed disposable local credential)

GRANT CONNECT ON DATABASE identity_service TO identity_service_migrator, identity_service_app;
CREATE SCHEMA identity AUTHORIZATION identity_service_migrator;
GRANT USAGE ON SCHEMA identity TO identity_service_app;

-- Runtime rights are granted explicitly after each migration. Future tables receive no
-- application privileges until their required operations are reviewed.
