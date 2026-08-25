from __future__ import annotations

from collections.abc import Callable

import pytest
from alembic import command
from sqlalchemy import Engine, create_engine, inspect, text

from identity_service.app import create_app
from identity_service.config import Settings
from identity_service.db.revisions import EXPECTED_MIGRATION_HEAD
from scripts.migrate_local import alembic_config, apply_local_runtime_grants
from tests.fixtures.fake_cognito import FakeCognito
from tests.http_client import ASGIClient
from tests.integration.conftest import DisposableDatabase

pytestmark = pytest.mark.integration


class MonotonicClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def database_settings(
    settings_factory: Callable[..., Settings], database_url: str, fake_cognito: FakeCognito
) -> Settings:
    return settings_factory(database_url=database_url, **fake_cognito.settings_overrides())


def _set_revisions(engine: Engine, *revisions: str) -> None:
    with engine.begin() as connection:
        connection.execute(text("DELETE FROM identity.alembic_version"))
        for revision in revisions:
            connection.execute(
                text("INSERT INTO identity.alembic_version (version_num) VALUES (:revision)"),
                {"revision": revision},
            )


def test_readiness_requires_exact_single_packaged_revision_and_recovers(
    settings_factory: Callable[..., Settings],
    runtime_database_url: str,
    migrator_engine: Engine,
    fake_cognito: FakeCognito,
) -> None:
    app = create_app(
        database_settings(settings_factory, runtime_database_url, fake_cognito),
        upstream_transport=fake_cognito.transport(),
    )
    try:
        with ASGIClient(app) as client:
            _set_revisions(migrator_engine, EXPECTED_MIGRATION_HEAD)
            assert client.get("/health/ready").status_code == 200

            for revisions in (
                (),
                ("0000_older",),
                ("9999_newer",),
                (EXPECTED_MIGRATION_HEAD, "unexpected_second_head"),
            ):
                _set_revisions(migrator_engine, *revisions)
                response = client.get("/health/ready")
                assert response.status_code == 503
                assert response.json()["code"] == "not_ready"

            _set_revisions(migrator_engine, EXPECTED_MIGRATION_HEAD)
            assert client.get("/health/ready").status_code == 200
    finally:
        _set_revisions(migrator_engine, EXPECTED_MIGRATION_HEAD)


def test_database_outage_keeps_liveness_healthy_and_readiness_recovers(
    settings_factory: Callable[..., Settings],
    runtime_database_url: str,
    fake_cognito: FakeCognito,
) -> None:
    app = create_app(
        settings_factory(
            database_url="postgresql+psycopg://app:local@127.0.0.1:1/db",  # pragma: allowlist secret (synthetic unavailable endpoint)  # noqa: E501
            **fake_cognito.settings_overrides(),
        ),
        upstream_transport=fake_cognito.transport(),
    )
    healthy_engine = create_engine(
        runtime_database_url,
        pool_pre_ping=True,
        hide_parameters=True,
        connect_args={"connect_timeout": 2, "options": "-c statement_timeout=1000"},
    )
    try:
        with ASGIClient(app) as client:
            assert client.get("/health/live").status_code == 200
            assert client.get("/health/ready").status_code == 503
            app.state.engine = healthy_engine
            assert client.get("/health/live").status_code == 200
            assert client.get("/health/ready").status_code == 200
    finally:
        healthy_engine.dispose()


def test_pool_exhaustion_makes_readiness_fail_safely(
    settings_factory: Callable[..., Settings],
    runtime_database_url: str,
    fake_cognito: FakeCognito,
) -> None:
    app = create_app(
        settings_factory(
            database_url=runtime_database_url,
            db_pool_size=1,
            db_max_overflow=0,
            db_pool_timeout_seconds=1,
            **fake_cognito.settings_overrides(),
        ),
        upstream_transport=fake_cognito.transport(),
    )
    with ASGIClient(app) as client, app.state.engine.connect():
        response = client.get("/health/ready")
        assert response.status_code == 503
        assert response.json()["code"] == "not_ready"


def test_startup_without_version_table_is_live_unready_and_performs_no_ddl(
    settings_factory: Callable[..., Settings],
    disposable_database: DisposableDatabase,
    fake_cognito: FakeCognito,
) -> None:
    app = create_app(
        database_settings(settings_factory, disposable_database.runtime_url, fake_cognito),
        upstream_transport=fake_cognito.transport(),
    )
    with ASGIClient(app) as client:
        assert client.get("/health/live").status_code == 200
        response = client.get("/health/ready")
        assert response.status_code == 503
        assert response.headers["content-type"] == "application/problem+json"
        assert response.json()["code"] == "not_ready"

    migrator = create_engine(disposable_database.migrator_url)
    try:
        assert inspect(migrator).get_table_names(schema="identity") == []
    finally:
        migrator.dispose()


def test_one_revision_base_state_is_live_but_not_ready(
    settings_factory: Callable[..., Settings],
    disposable_database: DisposableDatabase,
    fake_cognito: FakeCognito,
) -> None:
    config = alembic_config(disposable_database.migrator_url)
    command.upgrade(config, "head")
    apply_local_runtime_grants(disposable_database.migrator_url)
    command.downgrade(config, "base")

    migrator = create_engine(disposable_database.migrator_url)
    try:
        assert inspect(migrator).get_table_names(schema="identity") == ["alembic_version"]
        with migrator.connect() as connection:
            assert (
                connection.execute(text("SELECT version_num FROM identity.alembic_version")).all()
                == []
            )
    finally:
        migrator.dispose()

    app = create_app(
        database_settings(settings_factory, disposable_database.runtime_url, fake_cognito),
        upstream_transport=fake_cognito.transport(),
    )
    with ASGIClient(app) as client:
        assert client.get("/health/live").status_code == 200
        response = client.get("/health/ready")
        assert response.status_code == 503
        assert response.json()["code"] == "not_ready"


def test_jwks_initial_outage_is_live_unready_and_recovers_without_restart(
    settings_factory: Callable[..., Settings],
    runtime_database_url: str,
    fake_cognito: FakeCognito,
) -> None:
    clock = MonotonicClock()
    fake_cognito.jwks_status = 500
    app = create_app(
        settings_factory(
            database_url=runtime_database_url,
            jwks_refresh_min_interval_seconds=1,
            **fake_cognito.settings_overrides(),
        ),
        upstream_transport=fake_cognito.transport(),
        jwks_monotonic_clock=clock,
    )
    with ASGIClient(app) as client:
        assert client.get("/health/live").status_code == 200
        unavailable = client.get("/health/ready")
        assert unavailable.status_code == 503
        assert unavailable.json()["code"] == "not_ready"
        assert "cognito" not in unavailable.text.casefold()
        assert "jwks" not in unavailable.text.casefold()
        fake_cognito.jwks_status = 200
        clock.advance(1)
        assert client.get("/health/ready").status_code == 200


@pytest.mark.parametrize("mode", ["invalid_utf8", "deep_json"])
def test_malformed_initial_jwks_is_redacted_unready_and_recovers_without_restart(
    settings_factory: Callable[..., Settings],
    runtime_database_url: str,
    fake_cognito: FakeCognito,
    mode: str,
) -> None:
    clock = MonotonicClock()
    fake_cognito.jwks_mode = mode
    app = create_app(
        settings_factory(
            database_url=runtime_database_url,
            jwks_refresh_min_interval_seconds=1,
            **fake_cognito.settings_overrides(),
        ),
        upstream_transport=fake_cognito.transport(),
        jwks_monotonic_clock=clock,
    )
    with ASGIClient(app) as client:
        assert client.get("/health/live").status_code == 200
        unavailable = client.get("/health/ready")
        assert unavailable.status_code == 503
        assert unavailable.json()["code"] == "not_ready"
        assert mode not in unavailable.text
        assert app.state.jwks_cache._refreshing is False

        fake_cognito.jwks_mode = "valid"
        clock.advance(1)
        assert client.get("/health/ready").status_code == 200


def test_readiness_uses_bounded_stale_jwks_then_fails_hard_stale_and_recovers(
    settings_factory: Callable[..., Settings],
    runtime_database_url: str,
    fake_cognito: FakeCognito,
) -> None:
    clock = MonotonicClock()
    settings = settings_factory(
        database_url=runtime_database_url,
        jwks_cache_max_age_seconds=5,
        jwks_stale_if_error_seconds=20,
        jwks_refresh_min_interval_seconds=1,
        **fake_cognito.settings_overrides(),
    )
    app = create_app(
        settings,
        upstream_transport=fake_cognito.transport(),
        jwks_monotonic_clock=clock,
    )
    with ASGIClient(app) as client:
        assert client.get("/health/ready").status_code == 200
        original_snapshot = app.state.jwks_cache.snapshot
        fake_cognito.jwks_status = 500
        clock.advance(6)
        assert client.get("/health/ready").status_code == 200
        metrics = client.get("/metrics").text
        assert 'identity_service_jwks_cache_state{state="degraded"} 1.0' in metrics
        clock.advance(15)
        assert client.get("/health/ready").status_code == 503
        assert app.state.jwks_cache.snapshot is original_snapshot
        fake_cognito.jwks_status = 200
        clock.advance(1)
        assert client.get("/health/ready").status_code == 200


def test_malformed_jwks_refresh_preserves_usable_snapshot(
    settings_factory: Callable[..., Settings],
    runtime_database_url: str,
    fake_cognito: FakeCognito,
) -> None:
    clock = MonotonicClock()
    settings = settings_factory(
        database_url=runtime_database_url,
        jwks_cache_max_age_seconds=5,
        jwks_stale_if_error_seconds=20,
        jwks_refresh_min_interval_seconds=1,
        **fake_cognito.settings_overrides(),
    )
    app = create_app(
        settings,
        upstream_transport=fake_cognito.transport(),
        jwks_monotonic_clock=clock,
    )
    with ASGIClient(app) as client:
        assert client.get("/health/ready").status_code == 200
        original_snapshot = app.state.jwks_cache.snapshot
        fake_cognito.jwks_mode = "malformed_json"
        clock.advance(6)
        assert client.get("/health/ready").status_code == 200
        assert app.state.jwks_cache.snapshot is original_snapshot
