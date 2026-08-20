"""Bounded database and migration-head readiness check."""

from __future__ import annotations

from sqlalchemy import Engine, text
from sqlalchemy.exc import SQLAlchemyError

from identity_service.db.revisions import EXPECTED_MIGRATION_HEAD
from identity_service.observability.metrics import Metrics


def check_database_readiness(engine: Engine, metrics: Metrics) -> bool:
    try:
        with engine.connect() as connection:
            if connection.execute(text("SELECT 1")).scalar_one() != 1:
                metrics.set_readiness(False)
                return False
            revisions = tuple(
                connection.execute(
                    text("SELECT version_num FROM identity.alembic_version ORDER BY version_num")
                ).scalars()
            )
    except SQLAlchemyError:
        metrics.record_database_error("readiness")
        metrics.set_readiness(False)
        return False

    ready = revisions == (EXPECTED_MIGRATION_HEAD,)
    metrics.set_readiness(ready)
    return ready
