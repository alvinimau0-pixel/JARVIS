"""Restricted runtime role: the backend cannot alter, delete or unprotect audit entries.

The audit triggers from 0001 bind every role, but a table's owner (and any superuser) can
disable or drop them. Migrations therefore run as the owner, while the backend connects as a
login role that is a member of ``jarvis_app``: it may SELECT and INSERT audit rows and nothing
else on that table, and it owns nothing, so it cannot touch the triggers.

``jarvis_app`` is a NOLOGIN group role. Create the login role yourself (with a password) and
grant it membership, see docs/RECOVERY_PLAN.md. If the migrating role may not create roles and
``jarvis_app`` does not exist yet, this migration stops with an explanation.

Revision ID: 0002_app_role
Revises: 0001_foundation
Create Date: 2026-11-06
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0002_app_role"
down_revision: str | None = "0001_foundation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ROLE = "jarvis_app"
READ_WRITE = ("tasks", "approvals", "jobs", "events", "system_state", "devices")


def upgrade() -> None:
    op.execute(
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{ROLE}') THEN
                BEGIN
                    CREATE ROLE {ROLE} NOLOGIN;
                EXCEPTION WHEN insufficient_privilege THEN
                    RAISE EXCEPTION 'role {ROLE} does not exist and % may not create roles. '
                        'Ask a superuser to run: CREATE ROLE {ROLE} NOLOGIN;', current_user;
                END;
            END IF;
        END
        $$;
        """
    )
    op.execute(f"GRANT USAGE ON SCHEMA public TO {ROLE}")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {', '.join(READ_WRITE)} TO {ROLE}")
    # Append-only for the runtime role: no UPDATE, DELETE, TRUNCATE, TRIGGER or REFERENCES.
    op.execute(f"GRANT SELECT, INSERT ON audit_log TO {ROLE}")
    op.execute(f"GRANT SELECT ON alembic_version TO {ROLE}")
    op.execute(f"GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO {ROLE}")


def downgrade() -> None:
    # The role itself is cluster-wide and may hold login members; it is left in place.
    op.execute(f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {ROLE}")
    op.execute(f"REVOKE ALL ON alembic_version, audit_log, {', '.join(READ_WRITE)} FROM {ROLE}")
    op.execute(f"REVOKE USAGE ON SCHEMA public FROM {ROLE}")
