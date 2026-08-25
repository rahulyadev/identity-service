"""Create the initial identity data model.

Revision ID: 0001_initial_identity_schema
Revises: none
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial_identity_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SCHEMA = "identity"


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.Text(), server_default="active", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "(status = 'deleted' AND deleted_at IS NOT NULL) OR "
            "(status <> 'deleted' AND deleted_at IS NULL)",
            name="deleted_at_matches_status",
        ),
        sa.CheckConstraint("status IN ('active', 'disabled', 'deleted')", name="status_allowed"),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        schema=SCHEMA,
    )

    op.create_table(
        "provider_identities",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("issuer", sa.Text(), nullable=False),
        sa.Column("subject", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_auth_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claims_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "char_length(issuer) BETWEEN 1 AND 2048",
            name="issuer_length",
        ),
        sa.CheckConstraint(
            "char_length(subject) BETWEEN 1 AND 255",
            name="subject_length",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["identity.users.id"],
            name="fk_provider_identities_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_provider_identities"),
        sa.UniqueConstraint("issuer", "subject", name="uq_provider_identities_issuer_subject"),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_provider_identities_user_id",
        "provider_identities",
        ["user_id"],
        unique=False,
        schema=SCHEMA,
    )

    op.create_table(
        "profiles",
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("provider_email", sa.Text(), nullable=True),
        sa.Column("provider_email_verified", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("provider_display_name", sa.Text(), nullable=True),
        sa.Column("provider_avatar_url", sa.Text(), nullable=True),
        sa.Column("display_name_override", sa.Text(), nullable=True),
        sa.Column("version", sa.BigInteger(), server_default="1", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "display_name_override IS NULL OR char_length(display_name_override) <= 100",
            name="display_name_override_length",
        ),
        sa.CheckConstraint(
            "provider_avatar_url IS NULL OR char_length(provider_avatar_url) <= 2048",
            name="provider_avatar_url_length",
        ),
        sa.CheckConstraint(
            "provider_display_name IS NULL OR char_length(provider_display_name) <= 100",
            name="provider_display_name_length",
        ),
        sa.CheckConstraint(
            "provider_email IS NULL OR char_length(provider_email) BETWEEN 1 AND 320",
            name="provider_email_length",
        ),
        sa.CheckConstraint(
            "provider_email IS NOT NULL OR provider_email_verified = false",
            name="provider_email_verification_consistent",
        ),
        sa.CheckConstraint("version >= 1", name="version_positive"),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["identity.users.id"],
            name="fk_profiles_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("user_id", name="pk_profiles"),
        schema=SCHEMA,
    )


def downgrade() -> None:
    """Destructively remove all identity tables; disposable databases only."""

    op.drop_table("profiles", schema=SCHEMA)
    op.drop_index(
        "ix_provider_identities_user_id",
        table_name="provider_identities",
        schema=SCHEMA,
    )
    op.drop_table("provider_identities", schema=SCHEMA)
    op.drop_table("users", schema=SCHEMA)
