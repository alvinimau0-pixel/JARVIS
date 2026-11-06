"""Foundation schema: tasks, jobs, approvals, events, audit log, system state, devices.

Revision ID: 0001_foundation
Revises:
Create Date: 2026-11-06
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_foundation"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "tasks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_by_kind", sa.String(16), nullable=False),
        sa.Column("created_by_id", sa.String(128), nullable=False),
        sa.Column("created_at", TS, server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", TS, server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "status IN ('pending', 'running', 'waiting_approval', 'completed', 'failed', 'cancelled')",
            name="ck_tasks_status",
        ),
    )
    op.create_table(
        "approvals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("params", postgresql.JSONB(), nullable=False),
        sa.Column("params_hash", sa.String(64), nullable=False),
        sa.Column("level", sa.Integer(), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("requester_kind", sa.String(16), nullable=False),
        sa.Column("requester_id", sa.String(128), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("approver_id", sa.String(128), nullable=True),
        sa.Column("created_at", TS, server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("decided_at", TS, nullable=True),
        sa.Column("consumed_at", TS, nullable=True),
        sa.Column("execution_result", postgresql.JSONB(), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending', 'approved', 'denied', 'expired', 'consumed')",
            name="ck_approvals_status",
        ),
        sa.CheckConstraint(
            "requester_kind IN ('human', 'agent', 'system')", name="ck_approvals_requester"
        ),
        sa.CheckConstraint("level BETWEEN 0 AND 3", name="ck_approvals_level"),
    )
    op.create_index("ix_approvals_status", "approvals", ["status"])
    op.create_table(
        "jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "task_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tasks.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("owner", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column(
            "approval_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("approvals.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("stdout", sa.Text(), nullable=True),
        sa.Column("stderr", sa.Text(), nullable=True),
        sa.Column("output_truncated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", TS, server_default=sa.func.now(), nullable=False),
        sa.Column("started_at", TS, nullable=True),
        sa.Column("finished_at", TS, nullable=True),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'cancelled', 'timed_out')",
            name="ck_jobs_status",
        ),
    )
    op.create_index("ix_jobs_task_id", "jobs", ["task_id"])
    op.create_index("ix_jobs_status", "jobs", ["status"])
    op.create_table(
        "events",
        sa.Column("seq", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("type", sa.String(64), nullable=False),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("task_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("job_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("ts", TS, server_default=sa.func.now(), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
    )
    op.create_index("ix_events_task_id", "events", ["task_id"])
    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("ts", TS, nullable=False),
        sa.Column("actor_kind", sa.String(16), nullable=False),
        sa.Column("actor_id", sa.String(128), nullable=False),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("level", sa.Integer(), nullable=True),
        sa.Column("decision", sa.String(32), nullable=False),
        sa.Column("details", postgresql.JSONB(), nullable=False),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("hash", sa.String(64), nullable=False, unique=True),
    )
    # Append-only enforcement at the database level. Applies to every role, the app's included.
    op.execute(
        """
        CREATE FUNCTION audit_log_reject_mutation() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit_log is append-only (% rejected)', TG_OP
                USING ERRCODE = 'insufficient_privilege';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_log_no_update_delete
        BEFORE UPDATE OR DELETE ON audit_log
        FOR EACH ROW EXECUTE FUNCTION audit_log_reject_mutation();
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_log_no_truncate
        BEFORE TRUNCATE ON audit_log
        FOR EACH STATEMENT EXECUTE FUNCTION audit_log_reject_mutation();
        """
    )
    op.create_table(
        "system_state",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("value", postgresql.JSONB(), nullable=False),
        sa.Column("updated_at", TS, server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "devices",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("created_at", TS, server_default=sa.func.now(), nullable=False),
        sa.Column("revoked_at", TS, nullable=True),
    )


def downgrade() -> None:
    # Dropping the audit log destroys records. RECOVERY_PLAN.md requires a backup first.
    op.drop_table("devices")
    op.drop_table("system_state")
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log")
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_update_delete ON audit_log")
    op.drop_table("audit_log")
    op.execute("DROP FUNCTION IF EXISTS audit_log_reject_mutation()")
    op.drop_index("ix_events_task_id", table_name="events")
    op.drop_table("events")
    op.drop_index("ix_jobs_status", table_name="jobs")
    op.drop_index("ix_jobs_task_id", table_name="jobs")
    op.drop_table("jobs")
    op.drop_index("ix_approvals_status", table_name="approvals")
    op.drop_table("approvals")
    op.drop_table("tasks")
