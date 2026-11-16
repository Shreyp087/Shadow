"""Add target instructions and track workflow failures instead of endless Pending."""
from alembic import op
import sqlalchemy as sa

revision = "20261030_0004"
down_revision = "20261030_0003"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("target_systems", sa.Column("role", sa.String(120), nullable=False, server_default="General Assistant"))
    op.add_column("target_systems", sa.Column("system_prompt", sa.Text(), nullable=False, server_default=""))
    op.add_column("attack_runs", sa.Column("workflow_run_id", sa.String(128), nullable=True))
    op.add_column("attack_runs", sa.Column("failure_reason", sa.Text(), nullable=True))
    # Prior workers failed during their sandbox import, before begin_scan could
    # update the database. Preserve their evidence and expose an honest retry state.
    recovered = op.get_bind().execute(sa.text("""UPDATE attack_runs SET status = 'FAILED', completed_at = now(),
        failure_reason = 'The previous scan worker could not start. Start a new scan to retry.'
        WHERE status = 'PENDING' AND workflow_run_id IS NULL"""))
    print(f"Legacy Pending scans given a retry state: {recovered.rowcount}")


def downgrade():
    op.drop_column("attack_runs", "failure_reason")
    op.drop_column("attack_runs", "workflow_run_id")
    op.drop_column("target_systems", "system_prompt")
    op.drop_column("target_systems", "role")
