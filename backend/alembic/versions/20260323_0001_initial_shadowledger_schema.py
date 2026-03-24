"""Initial ShadowLedger schema.

Revision ID: 20260323_0001
Revises:
Create Date: 2026-03-23 18:30:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "20260323_0001"
down_revision = None
branch_labels = None
depends_on = None

attack_run_status = postgresql.ENUM(
    "PENDING",
    "RUNNING",
    "COMPLETED",
    "FAILED",
    name="attack_run_status",
    create_type=False,
)
target_system_type = postgresql.ENUM(
    "openai_compatible",
    "anthropic",
    name="target_system_type",
    create_type=False,
)
attack_vector_category = postgresql.ENUM(
    "PROMPT_INJECTION",
    "JAILBREAK",
    "DATA_EXTRACTION",
    "ROLE_CONFUSION",
    "INDIRECT_INJECTION",
    name="attack_vector_category",
    create_type=False,
)
severity_level = postgresql.ENUM(
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
    name="severity_level",
    create_type=False,
)
risk_category = postgresql.ENUM(
    "SAFE",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
    name="risk_category",
    create_type=False,
)


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    bind = op.get_bind()
    attack_run_status.create(bind, checkfirst=True)
    target_system_type.create(bind, checkfirst=True)
    attack_vector_category.create(bind, checkfirst=True)
    severity_level.create(bind, checkfirst=True)
    risk_category.create(bind, checkfirst=True)

    op.create_table(
        "users",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("clerk_user_id", sa.String(length=255), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("clerk_user_id", name=op.f("uq_users_clerk_user_id")),
    )
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=False)

    op.create_table(
        "attack_vectors",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("category", attack_vector_category, nullable=False),
        sa.Column("prompt_template", sa.Text(), nullable=False),
        sa.Column("severity", severity_level, nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_attack_vectors")),
    )
    op.create_index(op.f("ix_attack_vectors_category"), "attack_vectors", ["category"], unique=False)
    op.create_index(op.f("ix_attack_vectors_name"), "attack_vectors", ["name"], unique=False)
    op.create_index(op.f("ix_attack_vectors_severity"), "attack_vectors", ["severity"], unique=False)

    op.create_table(
        "target_systems",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("api_endpoint", sa.String(length=2048), nullable=False),
        sa.Column(
            "target_type",
            target_system_type,
            nullable=False,
            server_default=sa.text("'openai_compatible'"),
        ),
        sa.Column("api_key_encrypted", sa.Text(), nullable=False),
        sa.Column("model_name", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], name=op.f("fk_target_systems_user_id_users"), ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_target_systems")),
    )
    op.create_index(op.f("ix_target_systems_user_id"), "target_systems", ["user_id"], unique=False)

    op.create_table(
        "attack_runs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("target_system_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", attack_run_status, nullable=False, server_default=sa.text("'PENDING'")),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("total_attacks", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("vulnerabilities_found", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("risk_score_avg", sa.Numeric(precision=5, scale=2), nullable=True),
        sa.CheckConstraint("total_attacks >= 0", name=op.f("ck_attack_runs_total_attacks_non_negative")),
        sa.CheckConstraint(
            "vulnerabilities_found >= 0",
            name=op.f("ck_attack_runs_vulnerabilities_found_non_negative"),
        ),
        sa.ForeignKeyConstraint(
            ["target_system_id"],
            ["target_systems.id"],
            name=op.f("fk_attack_runs_target_system_id_target_systems"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_attack_runs_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_attack_runs")),
    )
    op.create_index(op.f("ix_attack_runs_target_system_id"), "attack_runs", ["target_system_id"], unique=False)
    op.create_index(op.f("ix_attack_runs_user_id"), "attack_runs", ["user_id"], unique=False)

    op.create_table(
        "attack_results",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("attack_run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("attack_vector_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("prompt_sent", sa.Text(), nullable=False),
        sa.Column("response_received", sa.Text(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("is_mutation", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("risk_category", risk_category, nullable=False),
        sa.Column("risk_reason", sa.Text(), nullable=False),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "risk_score >= 0 AND risk_score <= 100",
            name=op.f("ck_attack_results_risk_score_range"),
        ),
        sa.ForeignKeyConstraint(
            ["attack_run_id"],
            ["attack_runs.id"],
            name=op.f("fk_attack_results_attack_run_id_attack_runs"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["attack_vector_id"],
            ["attack_vectors.id"],
            name=op.f("fk_attack_results_attack_vector_id_attack_vectors"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_attack_results")),
    )
    op.create_index(op.f("ix_attack_results_attack_run_id"), "attack_results", ["attack_run_id"], unique=False)
    op.create_index(op.f("ix_attack_results_attack_vector_id"), "attack_results", ["attack_vector_id"], unique=False)
    op.create_index(op.f("ix_attack_results_risk_category"), "attack_results", ["risk_category"], unique=False)

    op.create_table(
        "trust_ledger_entries",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("attack_result_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("entry_hash", sa.String(length=64), nullable=False),
        sa.Column("prev_hash", sa.String(length=64), nullable=True),
        sa.Column("payload_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["attack_result_id"],
            ["attack_results.id"],
            name=op.f("fk_trust_ledger_entries_attack_result_id_attack_results"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_trust_ledger_entries")),
        sa.UniqueConstraint("entry_hash", name=op.f("uq_trust_ledger_entries_entry_hash")),
    )
    op.create_index(
        op.f("ix_trust_ledger_entries_attack_result_id"),
        "trust_ledger_entries",
        ["attack_result_id"],
        unique=False,
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION prevent_trust_ledger_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'trust_ledger_entries is append-only and cannot be updated or deleted';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trust_ledger_entries_no_mutation
        BEFORE UPDATE OR DELETE ON trust_ledger_entries
        FOR EACH ROW
        EXECUTE FUNCTION prevent_trust_ledger_mutation();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trust_ledger_entries_no_mutation ON trust_ledger_entries")
    op.execute("DROP FUNCTION IF EXISTS prevent_trust_ledger_mutation()")

    op.drop_index(op.f("ix_trust_ledger_entries_attack_result_id"), table_name="trust_ledger_entries")
    op.drop_table("trust_ledger_entries")

    op.drop_index(op.f("ix_attack_results_risk_category"), table_name="attack_results")
    op.drop_index(op.f("ix_attack_results_attack_vector_id"), table_name="attack_results")
    op.drop_index(op.f("ix_attack_results_attack_run_id"), table_name="attack_results")
    op.drop_table("attack_results")

    op.drop_index(op.f("ix_attack_runs_user_id"), table_name="attack_runs")
    op.drop_index(op.f("ix_attack_runs_target_system_id"), table_name="attack_runs")
    op.drop_table("attack_runs")

    op.drop_index(op.f("ix_target_systems_user_id"), table_name="target_systems")
    op.drop_table("target_systems")

    op.drop_index(op.f("ix_attack_vectors_severity"), table_name="attack_vectors")
    op.drop_index(op.f("ix_attack_vectors_name"), table_name="attack_vectors")
    op.drop_index(op.f("ix_attack_vectors_category"), table_name="attack_vectors")
    op.drop_table("attack_vectors")

    op.drop_index(op.f("ix_users_email"), table_name="users")
    op.drop_table("users")

    bind = op.get_bind()
    risk_category.drop(bind, checkfirst=True)
    severity_level.drop(bind, checkfirst=True)
    attack_vector_category.drop(bind, checkfirst=True)
    target_system_type.drop(bind, checkfirst=True)
    attack_run_status.drop(bind, checkfirst=True)
