"""Compare migrated PostgreSQL state with SQLAlchemy metadata."""

from __future__ import annotations

import os
from pathlib import Path

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine

from identity_service.models import Base

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    database_url = os.environ.get("TEST_MIGRATOR_DATABASE_URL")
    if not database_url:
        raise RuntimeError("TEST_MIGRATOR_DATABASE_URL is required")
    engine = create_engine(database_url, hide_parameters=True)
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(
                connection,
                opts={
                    "include_schemas": True,
                    "version_table_schema": "identity",
                    "compare_type": True,
                    "compare_server_default": True,
                },
            )
            differences = compare_metadata(context, Base.metadata)
    finally:
        engine.dispose()
    if differences:
        print(f"ORM/migration drift entries: {len(differences)}")
        return 1
    print("ORM metadata matches the migrated schema")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
