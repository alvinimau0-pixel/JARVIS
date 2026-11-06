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

## Migrations
Always back up before `alembic downgrade`. `0001` downgrade drops all tables including the audit
log. Never run downgrade against a database whose data matters.

## Credentials
`jarvis-backend secrets status database_url` / `set` / `delete`. Rotating the DB password:
change it in Postgres, then `secrets set database_url`. The session token rotates every launch.

## Local Postgres setup (example)
```sql
CREATE ROLE jarvis LOGIN PASSWORD '<choose one>';
CREATE DATABASE jarvis OWNER jarvis;
```
