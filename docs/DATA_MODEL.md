# Data model

PostgreSQL 16. Schema owned by Alembic (`backend/migrations`). Current head: `0001_foundation`.

| Table | Purpose | Key constraints |
|---|---|---|
| `tasks` | User-visible unit of work | `status` CHECK; `created_by_kind/id` |
| `jobs` | One execution under a task | FK `task_id` → tasks (CASCADE); FK `approval_id` → approvals (SET NULL); `status` CHECK; indexes on task_id, status |
| `approvals` | Hash-bound human approvals | `status` CHECK (pending/approved/denied/expired/consumed); `level` 0–3; `requester_kind` CHECK; `params_hash` |
| `events` | Ordered event log | `seq` IDENTITY PK (ordering); `id` UUID UNIQUE (dedupe); index task_id |
| `audit_log` | Tamper-evident audit | `hash` UNIQUE; `prev_hash` chain; trigger blocks UPDATE/DELETE/TRUNCATE |
| `system_state` | Key/value system flags | `emergency_stop` latch |
| `devices` | Placeholder for Phase 11 pairing | not exposed by any endpoint |

Deletion semantics: nothing in this phase deletes user data. Task deletion would cascade to
jobs; approvals survive (jobs reference them with SET NULL). The audit log is never deleted
by the application.

Not yet present: memory tables and pgvector (Phase 8). pgvector is only added if semantic
retrieval is justified.
