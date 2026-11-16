"""Add per-user LLM role settings.

Revision ID: 20260722_0002
Revises: 20260323_0001
Create Date: 2026-07-22 13:30:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "20260722_0002"
down_revision = "20260323_0001"
branch_labels = None
depends_on = None

llm_role = postgresql.ENUM(
    "attacker",
    "mutator",
    "judge",
    name="llm_role",
    create_type=False,
)
llm_provider = postgresql.ENUM(
    "hosted_openai",
    "local_openai_compatible",
    name="llm_provider",
    create_type=False,
)


def upgrade() -> None:
    bind = op.get_bind()
    llm_role.create(bind, checkfirst=True)
    llm_provider.create(bind, checkfirst=True)

    op.create_table(
        "llm_role_settings",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role", llm_role, nullable=False),
        sa.Column("provider", llm_provider, nullable=False),
        sa.Column("model_name", sa.String(length=255), nullable=False),
        sa.Column("base_url", sa.String(length=2048), nullable=True),
        sa.Column("api_key_encrypted", sa.Text(), nullable=True),
        sa.Column("api_key_provider", llm_provider, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_llm_role_settings_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_llm_role_settings")),
        sa.UniqueConstraint(
            "user_id",
            "role",
            name="uq_llm_role_settings_user_id_role",
        ),
    )
    op.create_index(
        op.f("ix_llm_role_settings_user_id"),
        "llm_role_settings",
        ["user_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_llm_role_settings_user_id"), table_name="llm_role_settings")
    op.drop_table("llm_role_settings")

    bind = op.get_bind()
    llm_provider.drop(bind, checkfirst=True)
    llm_role.drop(bind, checkfirst=True)
