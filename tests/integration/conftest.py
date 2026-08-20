from __future__ import annotations

import os
import re
import uuid
from collections.abc import Iterator
from dataclasses import dataclass

import pytest
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import make_url

from identity_service.db import build_session_factory
from identity_service.services.identity import IdentityProfileService


def required_url(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required; integration tests never substitute SQLite")
    if make_url(value).drivername != "postgresql+psycopg":
        raise RuntimeError(f"{name} must use postgresql+psycopg")
    return value


@pytest.fixture(scope="session")
def runtime_database_url() -> str:
    return required_url("TEST_DATABASE_URL")


@pytest.fixture(scope="session")
def migrator_database_url() -> str:
    return required_url("TEST_MIGRATOR_DATABASE_URL")


@pytest.fixture(scope="session")
def admin_database_url() -> str:
    return required_url("TEST_DATABASE_ADMIN_URL")


@pytest.fixture(scope="session")
def runtime_engine(runtime_database_url: str) -> Iterator[Engine]:
    engine = create_engine(
        runtime_database_url,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=50,
        pool_timeout=5,
        hide_parameters=True,
        connect_args={"options": "-c statement_timeout=5000", "connect_timeout": 3},
    )
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def migrator_engine(migrator_database_url: str) -> Iterator[Engine]:
    engine = create_engine(migrator_database_url, pool_pre_ping=True, hide_parameters=True)
    yield engine
    engine.dispose()


def clear_identity_data(engine: Engine) -> None:
    """Clear test data through the migrator, never the runtime role."""

    with engine.begin() as connection:
        connection.execute(text("DELETE FROM identity.profiles"))
        connection.execute(text("DELETE FROM identity.provider_identities"))
        connection.execute(text("DELETE FROM identity.users"))


@pytest.fixture
def identity_service(
    runtime_engine: Engine, migrator_engine: Engine
) -> Iterator[IdentityProfileService]:
    clear_identity_data(migrator_engine)
    yield IdentityProfileService(build_session_factory(runtime_engine))
    clear_identity_data(migrator_engine)


@dataclass(frozen=True)
class DisposableDatabase:
    name: str
    admin_url: str
    migrator_url: str
    runtime_url: str


def _url_for_database(raw_url: str, database: str) -> str:
    return make_url(raw_url).set(database=database).render_as_string(hide_password=False)


def _quoted_database(name: str) -> str:
    if not re.fullmatch(r"identity_test_[0-9a-f]{32}", name):
        raise ValueError("unsafe disposable database name")
    return f'"{name}"'


@pytest.fixture
def disposable_database(
    admin_database_url: str,
    migrator_database_url: str,
    runtime_database_url: str,
) -> Iterator[DisposableDatabase]:
    name = f"identity_test_{uuid.uuid4().hex}"
    quoted = _quoted_database(name)
    cluster_admin = create_engine(
        admin_database_url, isolation_level="AUTOCOMMIT", hide_parameters=True
    )
    with cluster_admin.connect() as connection:
        connection.execute(text(f"CREATE DATABASE {quoted}"))

    database_admin_url = _url_for_database(admin_database_url, name)
    database_admin = create_engine(database_admin_url, hide_parameters=True)
    try:
        with database_admin.begin() as connection:
            connection.execute(text(f"REVOKE ALL ON DATABASE {quoted} FROM PUBLIC"))
            connection.execute(
                text(
                    f"GRANT CONNECT ON DATABASE {quoted} TO "
                    "identity_service_migrator, identity_service_app"
                )
            )
            connection.execute(text("REVOKE CREATE ON SCHEMA public FROM PUBLIC"))
            connection.execute(
                text("CREATE SCHEMA identity AUTHORIZATION identity_service_migrator")
            )
            connection.execute(text("GRANT USAGE ON SCHEMA identity TO identity_service_app"))
        yield DisposableDatabase(
            name=name,
            admin_url=database_admin_url,
            migrator_url=_url_for_database(migrator_database_url, name),
            runtime_url=_url_for_database(runtime_database_url, name),
        )
    finally:
        database_admin.dispose()
        with cluster_admin.connect() as connection:
            connection.execute(text(f"DROP DATABASE {quoted} WITH (FORCE)"))
        cluster_admin.dispose()
