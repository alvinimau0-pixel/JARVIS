#!/usr/bin/env bash
# Development launcher: backend + Vite dev server sharing a throwaway per-run session token.
# Production uses the Tauri shell, which generates the token and passes it over IPC instead.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

: "${JARVIS_DATABASE_URL:?set JARVIS_DATABASE_URL (see docs/RECOVERY_PLAN.md for local Postgres setup)}"
: "${JARVIS_WORKSPACES:?set JARVIS_WORKSPACES to a comma-separated list of approved project folders}"
PORT="${JARVIS_PORT:-8765}"
TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"

(cd "$ROOT/backend" && uv run alembic upgrade head)

export JARVIS_SESSION_TOKEN="$TOKEN"
(cd "$ROOT/backend" && exec uv run jarvis-backend --port "$PORT") &
BACKEND_PID=$!
trap 'kill $BACKEND_PID 2>/dev/null || true' EXIT INT TERM

cd "$ROOT/apps/desktop"
VITE_JARVIS_API="http://127.0.0.1:$PORT" VITE_JARVIS_DEV_TOKEN="$TOKEN" pnpm dev
