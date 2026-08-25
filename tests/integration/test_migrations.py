from __future__ import annotations

import uuid

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.exc import DBAPIError

from identity_service.db.revisions import EXPECTED_MIGRATION_HEAD
from identity_service.models import Base, Profile, ProviderIdentity, User
from scripts.migrate_local import alembic_config, apply_local_runtime_grants
from tests.integration.conftest import DisposableDatabase

pytestmark = [pytest.mark.integration, pytest.mark.migration]


def upgrade(database: DisposableDatabase) -> None:
    command.upgrade(alembic_config(database.migrator_url), "head")
    apply_local_runtime_grants(database.migrator_url)


def test_exactly_one_migration_head() -> None:
    scripts = ScriptDirectory.from_config(alembic_config("postgresql+psycopg://unused/db"))
    assert scripts.get_heads() == [EXPECTED_MIGRATION_HEAD]


def test_empty_provisioned_database_upgrades_with_expected_schema(
    disposable_database: DisposableDatabase,
) -> None:
    upgrade(disposable_database)
    engine = create_engine(disposable_database.migrator_url)
    try:
        inspector = inspect(engine)
        assert set(inspector.get_table_names(schema="identity")) == {
            "alembic_version",
            "profiles",
            "provider_identities",
            "users",
        }
        assert inspector.get_table_names(schema="public") == []
        assert {
            item["name"] for item in inspector.get_check_constraints("users", schema="identity")
        } == {
            "ck_users_deleted_at_matches_status",
            "ck_users_status_allowed",
        }
        assert {
            item["name"]
            for item in inspector.get_check_constraints("provider_identities", schema="identity")
        } == {
            "ck_provider_identities_issuer_length",
            "ck_provider_identities_subject_length",
        }
        assert {
            item["name"] for item in inspector.get_check_constraints("profiles", schema="identity")
        } == {
            "ck_profiles_display_name_override_length",
            "ck_profiles_provider_avatar_url_length",
            "ck_profiles_provider_display_name_length",
            "ck_profiles_provider_email_length",
            "ck_profiles_provider_email_verification_consistent",
            "ck_profiles_version_positive",
        }
        assert {
            item["name"]
            for item in inspector.get_unique_constraints("provider_identities", schema="identity")
        } == {"uq_provider_identities_issuer_subject"}
        indexes = {
            item["name"]: item
            for item in inspector.get_indexes("provider_identities", schema="identity")
        }
        assert set(indexes) == {
            "ix_provider_identities_user_id",
            "uq_provider_identities_issuer_subject",
        }
        assert indexes["ix_provider_identities_user_id"]["unique"] is False
        assert indexes["uq_provider_identities_issuer_subject"]["unique"] is True
        assert indexes["uq_provider_identities_issuer_subject"]["duplicates_constraint"] == (
            "uq_provider_identities_issuer_subject"
        )
        provider_foreign_keys = inspector.get_foreign_keys("provider_identities", schema="identity")
        profile_foreign_keys = inspector.get_foreign_keys("profiles", schema="identity")
        assert provider_foreign_keys[0]["options"]["ondelete"] == "RESTRICT"
        assert profile_foreign_keys[0]["options"]["ondelete"] == "RESTRICT"
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT version_num FROM identity.alembic_version")
                ).scalar_one()
                == EXPECTED_MIGRATION_HEAD
            )
    finally:
        engine.dispose()


def test_destructive_downgrade_isolated_then_reupgrade(
    disposable_database: DisposableDatabase,
) -> None:
    config = alembic_config(disposable_database.migrator_url)
    command.upgrade(config, "head")
    engine = create_engine(disposable_database.migrator_url)
    try:
        with engine.begin() as connection:
            connection.execute(User.__table__.insert().values(id=uuid.uuid4()))
            assert connection.execute(select(User.id)).one() is not None
    finally:
        engine.dispose()
    command.downgrade(config, "base")
    engine = create_engine(disposable_database.migrator_url)
    try:
        assert inspect(engine).get_table_names(schema="identity") == ["alembic_version"]
    finally:
        engine.dispose()
    command.upgrade(config, "head")
    engine = create_engine(disposable_database.migrator_url)
    try:
        assert set(inspect(engine).get_table_names(schema="identity")) == {
            "alembic_version",
            "profiles",
            "provider_identities",
            "users",
        }
    finally:
        engine.dispose()


def test_orm_metadata_has_no_migration_drift(disposable_database: DisposableDatabase) -> None:
    upgrade(disposable_database)
    engine = create_engine(disposable_database.migrator_url)
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
            assert compare_metadata(context, Base.metadata) == []
    finally:
        engine.dispose()


def test_database_rejects_inconsistent_provider_email_state(
    disposable_database: DisposableDatabase,
) -> None:
    upgrade(disposable_database)
    runtime = create_engine(disposable_database.runtime_url)
    try:
        with runtime.begin() as connection:
            valid_user_id = uuid.uuid4()
            connection.execute(User.__table__.insert().values(id=valid_user_id))
            connection.execute(
                Profile.__table__.insert().values(
                    user_id=valid_user_id,
                    provider_email=None,
                    provider_email_verified=False,
                )
            )
            assert (
                connection.execute(
                    select(Profile.provider_email_verified).where(Profile.user_id == valid_user_id)
                ).scalar_one()
                is False
            )

        for provider_email, provider_email_verified in (
            (None, True),
            ("", False),
            ("x" * 321, False),
        ):
            invalid_user_id = uuid.uuid4()
            with pytest.raises(DBAPIError), runtime.begin() as connection:
                connection.execute(User.__table__.insert().values(id=invalid_user_id))
                connection.execute(
                    Profile.__table__.insert().values(
                        user_id=invalid_user_id,
                        provider_email=provider_email,
                        provider_email_verified=provider_email_verified,
                    )
                )
    finally:
        runtime.dispose()


def test_runtime_role_has_exact_service_dml_but_no_ddl_or_destructive_rights(
    disposable_database: DisposableDatabase,
) -> None:
    upgrade(disposable_database)
    runtime = create_engine(disposable_database.runtime_url)
    runtime_autocommit = create_engine(
        disposable_database.runtime_url, isolation_level="AUTOCOMMIT"
    )
    admin = create_engine(disposable_database.admin_url)
    admin_autocommit = create_engine(disposable_database.admin_url, isolation_level="AUTOCOMMIT")
    user_id = uuid.uuid4()
    provider_id = uuid.uuid4()
    forbidden_database = f"identity_forbidden_{uuid.uuid4().hex}"
    database_was_created = False
    try:
        with runtime.connect() as connection:
            assert connection.execute(text("SELECT current_user")).scalar_one() == (
                "identity_service_app"
            )
            assert connection.execute(text("SELECT current_database()")).scalar_one() == (
                disposable_database.name
            )
            assert (
                connection.execute(
                    text("SELECT has_schema_privilege(current_user, 'identity', 'CREATE')")
                ).scalar_one()
                is False
            )
            with pytest.raises(DBAPIError):
                connection.execute(text("CREATE TABLE identity.forbidden (id integer)"))
            connection.rollback()
            with pytest.raises(DBAPIError):
                connection.execute(text("CREATE SCHEMA forbidden_runtime_schema"))
            connection.rollback()
            with pytest.raises(DBAPIError):
                connection.execute(text("ALTER SCHEMA identity RENAME TO forbidden_identity"))
            connection.rollback()
            with pytest.raises(DBAPIError):
                connection.execute(text("ALTER TABLE identity.users ADD COLUMN forbidden integer"))
            connection.rollback()
            with pytest.raises(DBAPIError):
                connection.execute(text("CREATE ROLE forbidden_runtime_role"))
            connection.rollback()
            with pytest.raises(DBAPIError):
                connection.execute(text("SET ROLE identity_service_migrator"))
            connection.rollback()

        with runtime_autocommit.connect() as connection:
            try:
                connection.execute(text(f'CREATE DATABASE "{forbidden_database}"'))
            except DBAPIError:
                pass
            else:
                database_was_created = True
        assert not database_was_created, "runtime role unexpectedly created a database"

        with runtime.begin() as connection:
            connection.execute(User.__table__.insert().values(id=user_id))
            connection.execute(
                ProviderIdentity.__table__.insert().values(
                    id=provider_id,
                    user_id=user_id,
                    issuer="issuer",
                    subject="opaque",
                    last_seen_at=text("CURRENT_TIMESTAMP"),
                )
            )
            connection.execute(Profile.__table__.insert().values(user_id=user_id))
            assert (
                connection.execute(select(User.id).where(User.id == user_id)).scalar_one()
                == user_id
            )
            connection.execute(
                ProviderIdentity.__table__.update()
                .where(ProviderIdentity.id == provider_id)
                .values(
                    last_seen_at=text("CURRENT_TIMESTAMP"),
                    last_auth_time=text("CURRENT_TIMESTAMP"),
                    claims_synced_at=text("CURRENT_TIMESTAMP"),
                )
            )
            connection.execute(
                Profile.__table__.update()
                .where(Profile.user_id == user_id)
                .values(
                    provider_email="updated@example.invalid",
                    provider_email_verified=True,
                    provider_display_name="Updated",
                    provider_avatar_url="https://cdn.invalid/updated.png",
                    display_name_override="Local",
                    version=2,
                    updated_at=text("CURRENT_TIMESTAMP"),
                )
            )

        denied_statements = (
            "DELETE FROM identity.profiles",
            "DELETE FROM identity.provider_identities",
            "DELETE FROM identity.users",
            "UPDATE identity.users SET status = 'disabled' WHERE id = :user_id",
            "UPDATE identity.users SET deleted_at = CURRENT_TIMESTAMP WHERE id = :user_id",
            "UPDATE identity.provider_identities SET issuer = 'changed' WHERE id = :provider_id",
            "UPDATE identity.provider_identities SET subject = 'changed' WHERE id = :provider_id",
            "UPDATE identity.provider_identities SET user_id = :user_id WHERE id = :provider_id",
            "UPDATE identity.profiles SET user_id = :user_id WHERE user_id = :user_id",
            "UPDATE identity.profiles SET created_at = CURRENT_TIMESTAMP WHERE user_id = :user_id",
            "INSERT INTO identity.alembic_version (version_num) VALUES ('forbidden')",
            "UPDATE identity.alembic_version SET version_num = 'forbidden'",
            "DELETE FROM identity.alembic_version",
        )
        for statement in denied_statements:
            parameters: dict[str, object] = {}
            if ":user_id" in statement:
                parameters["user_id"] = user_id
            if ":provider_id" in statement:
                parameters["provider_id"] = provider_id
            with runtime.connect() as connection, pytest.raises(DBAPIError):
                connection.execute(text(statement), parameters)

        with admin.connect() as connection:
            role_attributes = connection.execute(
                text(
                    "SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolreplication "
                    "FROM pg_roles WHERE rolname IN "
                    "('identity_service_app', 'identity_service_migrator') ORDER BY rolname"
                )
            ).all()
            assert [tuple(row) for row in role_attributes] == [
                ("identity_service_app", False, False, False, False),
                ("identity_service_migrator", False, False, False, False),
            ]
            ownership = connection.execute(
                text(
                    "SELECT d.datname, pg_get_userbyid(d.datdba), n.nspname, "
                    "pg_get_userbyid(n.nspowner) FROM pg_database d "
                    "JOIN pg_namespace n ON n.nspname = 'identity' "
                    "WHERE d.datname = current_database()"
                )
            ).one()
            assert tuple(ownership) == (
                disposable_database.name,
                "postgres",
                "identity",
                "identity_service_migrator",
            )
            table_owners = connection.execute(
                text(
                    "SELECT tablename, tableowner FROM pg_tables "
                    "WHERE schemaname = 'identity' ORDER BY tablename"
                )
            ).all()
            assert [tuple(row) for row in table_owners] == [
                ("alembic_version", "identity_service_migrator"),
                ("profiles", "identity_service_migrator"),
                ("provider_identities", "identity_service_migrator"),
                ("users", "identity_service_migrator"),
            ]
            table_grants = connection.execute(
                text(
                    "SELECT table_name, privilege_type, is_grantable "
                    "FROM information_schema.role_table_grants "
                    "WHERE grantee = 'identity_service_app' AND table_schema = 'identity' "
                    "ORDER BY table_name, privilege_type"
                )
            ).all()
            expected_grants = {
                (table_name, privilege, "NO")
                for table_name in ("profiles", "provider_identities", "users")
                for privilege in ("INSERT", "SELECT")
            }
            expected_grants.add(("alembic_version", "SELECT", "NO"))
            assert {tuple(row) for row in table_grants} == expected_grants
            update_grants = connection.execute(
                text(
                    "SELECT table_name, column_name, privilege_type, is_grantable "
                    "FROM information_schema.role_column_grants "
                    "WHERE grantee = 'identity_service_app' AND table_schema = 'identity' "
                    "AND privilege_type = 'UPDATE' ORDER BY table_name, column_name"
                )
            ).all()
            assert {tuple(row) for row in update_grants} == {
                ("profiles", column, "UPDATE", "NO")
                for column in (
                    "display_name_override",
                    "provider_avatar_url",
                    "provider_display_name",
                    "provider_email",
                    "provider_email_verified",
                    "updated_at",
                    "version",
                )
            } | {
                ("provider_identities", column, "UPDATE", "NO")
                for column in ("claims_synced_at", "last_auth_time", "last_seen_at")
            }
            for table_name in ("users", "provider_identities", "profiles"):
                assert not connection.execute(
                    text("SELECT has_table_privilege('identity_service_app', :table, 'DELETE')"),
                    {"table": f"identity.{table_name}"},
                ).scalar_one()
                assert not connection.execute(
                    text("SELECT has_table_privilege('identity_service_app', :table, 'UPDATE')"),
                    {"table": f"identity.{table_name}"},
                ).scalar_one()
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM pg_default_acl "
                        "WHERE pg_get_userbyid(defaclrole) = 'identity_service_migrator' "
                        "AND array_to_string(defaclacl, ',') LIKE '%identity_service_app%'"
                    )
                ).scalar_one()
                == 0
            )
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM information_schema.sequences "
                        "WHERE sequence_schema = 'identity'"
                    )
                ).scalar_one()
                == 0
            )
    finally:
        if database_was_created:
            with admin_autocommit.connect() as connection:
                connection.execute(text(f'DROP DATABASE "{forbidden_database}" WITH (FORCE)'))
        runtime.dispose()
        runtime_autocommit.dispose()
        admin.dispose()
        admin_autocommit.dispose()
