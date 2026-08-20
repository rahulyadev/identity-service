from __future__ import annotations

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import Literal

import pytest
from sqlalchemy import Engine, create_engine, func, select, text, update
from sqlalchemy.exc import DBAPIError, SQLAlchemyError
from sqlalchemy.exc import TimeoutError as SQLAlchemyTimeoutError
from sqlalchemy.orm import Session

from identity_service.db import build_session_factory
from identity_service.models import Profile, ProviderIdentity, User, UserStatus
from identity_service.services import (
    IdentityNotFoundError,
    IdentityProfileService,
    ProviderIdentityInput,
    ProviderProfileInput,
    UserUnavailableError,
    VersionConflictError,
)
from identity_service.services.identity import CreationStep, advisory_lock_key

pytestmark = pytest.mark.integration


def identity(
    subject: str = "opaque-subject",
    *,
    issuer: str = "https://issuer.invalid/exact",
    auth_time: datetime | None = None,
) -> ProviderIdentityInput:
    return ProviderIdentityInput(
        issuer=issuer,
        subject=subject,
        auth_time=auth_time or datetime(2026, 1, 1, tzinfo=UTC),
    )


def profile(
    *,
    email: str | None = "person@example.invalid",
    email_verified: bool | None = None,
    display_name: str | None = "Provider Name",
    avatar_url: str | None = "https://cdn.invalid/avatar.png",
) -> ProviderProfileInput:
    return ProviderProfileInput(
        email=email,
        email_verified=email is not None if email_verified is None else email_verified,
        display_name=display_name,
        avatar_url=avatar_url,
    )


def counts(engine: Engine) -> tuple[int, int, int]:
    with engine.connect() as connection:
        return (
            connection.execute(select(func.count()).select_from(User)).scalar_one(),
            connection.execute(select(func.count()).select_from(ProviderIdentity)).scalar_one(),
            connection.execute(select(func.count()).select_from(Profile)).scalar_one(),
        )


def test_new_and_returning_bootstrap_create_one_stable_identity(
    identity_service: IdentityProfileService, runtime_engine: Engine
) -> None:
    first = identity_service.bootstrap_identity(identity("not-a-uuid"), profile())
    second = identity_service.bootstrap_identity(identity("not-a-uuid"), profile())
    assert first.user_id == second.user_id
    assert first.user_id.version == 4
    assert second.version == 1
    assert counts(runtime_engine) == (1, 1, 1)


def test_same_email_never_merges_different_subjects(
    identity_service: IdentityProfileService, runtime_engine: Engine
) -> None:
    first = identity_service.bootstrap_identity(identity("subject-one"), profile())
    second = identity_service.bootstrap_identity(identity("subject-two"), profile())
    assert first.user_id != second.user_id
    assert counts(runtime_engine) == (2, 2, 2)


def test_email_change_preserves_user_id(identity_service: IdentityProfileService) -> None:
    first = identity_service.bootstrap_identity(identity(), profile(email="first@example.invalid"))
    second = identity_service.bootstrap_identity(
        identity(), profile(email="second@example.invalid")
    )
    assert first.user_id == second.user_id
    assert second.provider_email == "second@example.invalid"
    assert second.version == 2


def test_issuer_and_subject_comparisons_are_exact_and_case_sensitive(
    identity_service: IdentityProfileService, runtime_engine: Engine
) -> None:
    values = [
        identity("Subject", issuer="Issuer"),
        identity("subject", issuer="Issuer"),
        identity("Subject", issuer="issuer"),
    ]
    user_ids = {identity_service.bootstrap_identity(value, profile()).user_id for value in values}
    assert len(user_ids) == 3
    assert counts(runtime_engine) == (3, 3, 3)


def test_provider_sync_clears_omitted_fields_preserves_override_and_versions_effective_changes(
    identity_service: IdentityProfileService,
) -> None:
    created = identity_service.bootstrap_identity(identity(), profile())
    overridden = identity_service.update_display_name(created.user_id, 1, "  Local Name  ")
    assert overridden.version == 2
    assert overridden.display_name_override == "Local Name"

    changed = identity_service.bootstrap_identity(
        identity(),
        profile(display_name="Changed Provider", avatar_url="https://cdn.invalid/new.png"),
    )
    assert changed.version == 3
    assert changed.display_name_override == "Local Name"
    assert changed.effective_display_name == "Local Name"

    cleared = identity_service.bootstrap_identity(
        identity(), profile(email=None, display_name=None, avatar_url=None)
    )
    assert cleared.version == 4
    assert cleared.provider_email is None
    assert cleared.provider_email_verified is False
    assert cleared.provider_display_name is None
    assert cleared.provider_avatar_url is None
    assert cleared.display_name_override == "Local Name"

    no_op = identity_service.bootstrap_identity(
        identity(), profile(email=None, display_name=None, avatar_url=None)
    )
    assert no_op.version == 4


def test_display_name_update_is_atomic_noop_clear_and_conflict(
    identity_service: IdentityProfileService,
) -> None:
    created = identity_service.bootstrap_identity(identity(), profile())
    updated = identity_service.update_display_name(created.user_id, 1, "Local")
    assert updated.version == 2
    assert updated.effective_display_name == "Local"

    no_op = identity_service.update_display_name(created.user_id, 2, "Local")
    assert no_op.version == 2

    with pytest.raises(VersionConflictError):
        identity_service.update_display_name(created.user_id, 1, "Stale")

    cleared = identity_service.update_display_name(created.user_id, 2, None)
    assert cleared.version == 3
    assert cleared.effective_display_name == "Provider Name"


def test_profile_lookup_not_found(identity_service: IdentityProfileService) -> None:
    with pytest.raises(IdentityNotFoundError):
        identity_service.get_profile_for_identity("issuer", "unknown")


@pytest.mark.parametrize("status", [UserStatus.DISABLED, UserStatus.DELETED])
def test_disabled_and_deleted_users_cannot_bootstrap_read_or_update(
    identity_service: IdentityProfileService,
    migrator_engine: Engine,
    status: UserStatus,
) -> None:
    created = identity_service.bootstrap_identity(identity(), profile())
    values: dict[str, object] = {"status": status.value}
    if status is UserStatus.DELETED:
        values["deleted_at"] = datetime.now(UTC)
    with migrator_engine.begin() as connection:
        connection.execute(update(User).where(User.id == created.user_id).values(**values))

    with pytest.raises(UserUnavailableError):
        identity_service.bootstrap_identity(identity(), profile())
    with pytest.raises(UserUnavailableError):
        identity_service.get_profile_for_identity(identity().issuer, identity().subject)
    with pytest.raises(UserUnavailableError):
        identity_service.update_display_name(created.user_id, created.version, "Blocked")


def test_last_auth_time_never_moves_backwards(
    identity_service: IdentityProfileService, runtime_engine: Engine
) -> None:
    latest = datetime(2026, 2, 1, tzinfo=UTC)
    older = latest - timedelta(days=1)
    identity_service.bootstrap_identity(identity(auth_time=latest), profile())
    identity_service.bootstrap_identity(identity(auth_time=older), profile())
    with runtime_engine.connect() as connection:
        stored = connection.execute(select(ProviderIdentity.last_auth_time)).scalar_one()
        synced = connection.execute(select(ProviderIdentity.claims_synced_at)).scalar_one()
        seen = connection.execute(select(ProviderIdentity.last_seen_at)).scalar_one()
    assert stored == latest
    assert synced is not None
    assert seen is not None


class FailingIdentityService(IdentityProfileService):
    def __init__(
        self,
        *args: object,
        fail_step: CreationStep,
        failure: Literal["application", "statement"] = "application",
        **kwargs: object,
    ) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.fail_step = fail_step
        self.failure = failure

    def _after_create_step(self, session: Session, step: CreationStep) -> None:
        if step != self.fail_step:
            return
        if self.failure == "statement":
            session.execute(text("SELECT 1 / 0"))
        raise RuntimeError(f"forced failure after {step}")


@pytest.mark.parametrize("step", ["user", "provider_identity", "profile"])
def test_failure_at_every_creation_step_leaves_no_orphans(
    runtime_engine: Engine, migrator_engine: Engine, step: CreationStep
) -> None:
    from tests.integration.conftest import clear_identity_data

    clear_identity_data(migrator_engine)
    service = FailingIdentityService(build_session_factory(runtime_engine), fail_step=step)
    with pytest.raises(RuntimeError, match="forced failure"):
        service.bootstrap_identity(identity(), profile())
    assert counts(runtime_engine) == (0, 0, 0)


def test_database_statement_failure_rolls_back_whole_transaction(
    runtime_engine: Engine, migrator_engine: Engine
) -> None:
    from tests.integration.conftest import clear_identity_data

    clear_identity_data(migrator_engine)
    service = FailingIdentityService(
        build_session_factory(runtime_engine),
        fail_step="provider_identity",
        failure="statement",
    )
    with pytest.raises(SQLAlchemyError):
        service.bootstrap_identity(identity(), profile())
    assert counts(runtime_engine) == (0, 0, 0)


@pytest.mark.timeout(60)
def test_fifty_concurrent_bootstraps_create_exactly_one_identity(
    runtime_engine: Engine,
    migrator_engine: Engine,
) -> None:
    from tests.integration.conftest import clear_identity_data

    clear_identity_data(migrator_engine)
    service = IdentityProfileService(build_session_factory(runtime_engine))
    barrier = threading.Barrier(50)

    def bootstrap() -> uuid.UUID:
        barrier.wait()
        return service.bootstrap_identity(identity(), profile()).user_id

    with ThreadPoolExecutor(max_workers=50) as executor:
        user_ids = list(executor.map(lambda _: bootstrap(), range(50)))

    assert len(set(user_ids)) == 1
    assert counts(runtime_engine) == (1, 1, 1)
    lock_key = advisory_lock_key(identity().issuer, identity().subject)
    with runtime_engine.begin() as connection:
        assert connection.execute(
            text("SELECT pg_try_advisory_lock(:lock_key)"), {"lock_key": lock_key}
        ).scalar_one()
        assert connection.execute(
            text("SELECT pg_advisory_unlock(:lock_key)"), {"lock_key": lock_key}
        ).scalar_one()


def test_concurrent_display_name_updates_allow_exactly_one_expected_version(
    identity_service: IdentityProfileService,
) -> None:
    created = identity_service.bootstrap_identity(identity(), profile())
    barrier = threading.Barrier(20)

    def update_name(index: int) -> str:
        barrier.wait()
        try:
            identity_service.update_display_name(created.user_id, 1, f"Name {index}")
        except VersionConflictError:
            return "conflict"
        return "updated"

    with ThreadPoolExecutor(max_workers=20) as executor:
        outcomes = list(executor.map(update_name, range(20)))

    assert outcomes.count("updated") == 1
    assert outcomes.count("conflict") == 19
    current = identity_service.get_profile_for_identity(identity().issuer, identity().subject)
    assert current.version == 2
    assert current.provider_email == "person@example.invalid"
    assert current.provider_email_verified is True
    assert current.provider_display_name == "Provider Name"
    assert current.provider_avatar_url == "https://cdn.invalid/avatar.png"


def test_pool_exhaustion_fails_bounded_without_partial_rows(
    runtime_database_url: str, runtime_engine: Engine, migrator_engine: Engine
) -> None:
    from tests.integration.conftest import clear_identity_data

    clear_identity_data(migrator_engine)
    exhausted_engine = create_engine(
        runtime_database_url,
        pool_size=1,
        max_overflow=0,
        pool_timeout=1,
        hide_parameters=True,
    )
    service = IdentityProfileService(build_session_factory(exhausted_engine))
    try:
        with exhausted_engine.connect(), pytest.raises(SQLAlchemyTimeoutError):
            service.bootstrap_identity(identity(), profile())
    finally:
        exhausted_engine.dispose()
    assert counts(runtime_engine) == (0, 0, 0)


def test_statement_timeout_cancels_query_and_connection_recovers(
    runtime_database_url: str,
) -> None:
    timeout_engine = create_engine(
        runtime_database_url,
        pool_pre_ping=True,
        hide_parameters=True,
        connect_args={"connect_timeout": 2, "options": "-c statement_timeout=100"},
    )
    try:
        with timeout_engine.connect() as connection:
            with pytest.raises(DBAPIError):
                connection.execute(text("SELECT pg_sleep(1)"))
            connection.rollback()
            assert connection.execute(text("SELECT 1")).scalar_one() == 1
    finally:
        timeout_engine.dispose()


def test_terminated_connection_is_invalidated_and_pool_recovers(
    runtime_database_url: str, admin_database_url: str
) -> None:
    application = create_engine(runtime_database_url, pool_pre_ping=True, hide_parameters=True)
    administrator = create_engine(admin_database_url, hide_parameters=True)
    try:
        with application.connect() as victim:
            backend_pid = victim.execute(text("SELECT pg_backend_pid()")).scalar_one()
            with administrator.begin() as connection:
                assert connection.execute(
                    text("SELECT pg_terminate_backend(:backend_pid)"),
                    {"backend_pid": backend_pid},
                ).scalar_one()
            with pytest.raises(DBAPIError):
                victim.execute(text("SELECT 1"))
            assert victim.invalidated
        with application.connect() as recovered:
            assert recovered.execute(text("SELECT 1")).scalar_one() == 1
    finally:
        application.dispose()
        administrator.dispose()
