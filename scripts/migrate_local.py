"""Upgrade a local database and apply its least-privilege local runtime grants."""

from __future__ import annotations

import os
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text

ROOT = Path(__file__).resolve().parents[1]
LOCAL_RUNTIME_ROLE = "identity_service_app"


def _database_url() -> str:
    value = os.environ.get("DATABASE_URL")
    if not value:
        raise RuntimeError("DATABASE_URL is required")
    return value


def alembic_config(database_url: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return config


def apply_local_runtime_grants(database_url: str) -> None:
    engine = create_engine(database_url, hide_parameters=True)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA identity "
                    f"FROM {LOCAL_RUNTIME_ROLE}"
                )
            )
            connection.execute(
                text(
                    "REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA identity "
                    f"FROM {LOCAL_RUNTIME_ROLE}"
                )
            )
            connection.execute(
                text(
                    "GRANT SELECT, INSERT ON identity.users, "
                    "identity.provider_identities, identity.profiles "
                    f"TO {LOCAL_RUNTIME_ROLE}"
                )
            )
            connection.execute(
                text(f"GRANT SELECT ON identity.alembic_version TO {LOCAL_RUNTIME_ROLE}")
            )
            connection.execute(
                text(
                    "GRANT UPDATE (last_seen_at, last_auth_time, claims_synced_at) "
                    "ON identity.provider_identities "
                    f"TO {LOCAL_RUNTIME_ROLE}"
                )
            )
            connection.execute(
                text(
                    "GRANT UPDATE (provider_email, provider_email_verified, "
                    "provider_display_name, provider_avatar_url, display_name_override, "
                    "version, updated_at) ON identity.profiles "
                    f"TO {LOCAL_RUNTIME_ROLE}"
                )
            )
    finally:
        engine.dispose()


def main() -> None:
    database_url = _database_url()
    command.upgrade(alembic_config(database_url), "head")
    apply_local_runtime_grants(database_url)


if __name__ == "__main__":
    main()
