"""Add Anthropic as an internal role provider without changing existing rows."""
from alembic import op

revision = "20261030_0003"
down_revision = "20260722_0002"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("ALTER TYPE llm_provider ADD VALUE IF NOT EXISTS 'hosted_anthropic'")


def downgrade():
    # Postgres cannot remove an enum label safely while existing rows use it.
    # Retain the additive label; no credentials or role overrides are rewritten.
    pass
