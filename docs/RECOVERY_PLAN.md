# Recovery plan

## Start / stop
- Dev: `scripts/dev.sh` (Ctrl+C stops both). Desktop: closing the app kills the backend.
- Health: `GET /api/v1/health` (UI: Health drawer).

## Backend crash or restart
On startup the backend marks jobs left `queued/running` as `failed` ("backend restarted while job
was active; outcome unknown"), audits it, and emits `system.recovered` with the PIDs it could not
verify. **Check those PIDs manually**: an orphaned child from the previous run is not killed
automatically, because PIDs may have been reused.

## Emergency stop
Latch persists across restarts. Reset: Health drawer → "Request emergency-stop reset (L3)" →
approve → run. If the UI is unavailable, use the API with the same two-step flow.

## Database backup and restore
```bash
pg_dump --format=custom --file jarvis-$(date +%F).dump "$DATABASE_URL_WITHOUT_DRIVER"
pg_restore --clean --if-exists --dbname "$DATABASE_URL_WITHOUT_DRIVER" jarvis-YYYY-MM-DD.dump
```
(`DATABASE_URL_WITHOUT_DRIVER` = the URL with `postgresql://` instead of `postgresql+psycopg://`.)
`pg_restore --clean` must drop the audit triggers' table: restore into an empty database instead
when possible. After restore run `alembic upgrade head` and `GET /api/v1/audit/verify`.
**A tested restore drill is still open (KI-008).**

## Audit verification fails
`GET /api/v1/audit/verify` (UI: Audit drawer) names the first bad entry or the anchor problem.
- *"does not match its keyed hash … or the audit key changed"*: either tampering, or the audit
  key in the credential store is not the one the log was written with (e.g. a new machine).
  Restore the original key with `jarvis-backend secrets set audit_hmac_key`. Keep a copy of the
  key with your backups; without it the old chain cannot be verified.
- *"anchored entry N is missing / was replaced"*: entries were removed from the end, or the
  database was restored/reset while `~/.jarvis/audit-anchor.jsonl` still describes the old one.
  After a deliberate restore or reset, move the anchor file aside (keep it as evidence).

Do not try to "repair" the chain: keep the database as evidence and start a fresh one.

## Migrations
Always back up before `alembic downgrade`. `0001` downgrade drops all tables including the audit
log. Never run downgrade against a database whose data matters.

## Credentials
`jarvis-backend secrets status database_url` / `set` / `delete` (likewise `audit_hmac_key`).
Rotating the DB password: change it in Postgres, then `secrets set database_url`. The session
token rotates every launch; agent tokens die with the backend and with every emergency stop.

## Local Postgres setup (example)
Two login roles: `jarvis` owns the schema and runs migrations; `jarvis_runtime` is what the
backend connects as, and through `jarvis_app` it can only append to the audit log.
```sql
CREATE ROLE jarvis LOGIN PASSWORD '<choose one>';
CREATE DATABASE jarvis OWNER jarvis;
CREATE ROLE jarvis_app NOLOGIN;                     -- or let migration 0002 create it
CREATE ROLE jarvis_runtime LOGIN PASSWORD '<another one>' IN ROLE jarvis_app;
```
Run migrations as the owner, then store the runtime URL for the backend:
```bash
cd backend
JARVIS_DATABASE_URL=postgresql+psycopg://jarvis:<pw>@127.0.0.1:5432/jarvis uv run alembic upgrade head
uv run jarvis-backend secrets set database_url
#   postgresql+psycopg://jarvis_runtime:<pw>@127.0.0.1:5432/jarvis
```
The Health drawer's `audit_protection` check turns green once the backend connects this way.
