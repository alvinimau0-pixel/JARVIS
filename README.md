# JARVIS OS

A secure, local-first personal AI operating environment. The PC is the host; an iPhone
companion (later phase) connects over an authenticated private network.

> **Status: Phases 0–2 (discovery, foundation, security core).** No AI provider, Claude Code,
> Codex, voice, memory or iPhone features exist yet. The UI says so wherever they would appear.
> See [`docs/BUILD_STATUS.md`](docs/BUILD_STATUS.md) for verified status and
> [`docs/KNOWN_ISSUES.md`](docs/KNOWN_ISSUES.md) for what is incomplete or untested.

## What works today

- **Three-section desktop UI** (CLAUDE · CODEX · BRAIN & WORKFLOW) with a live Three.js core
  whose state is driven only by real backend events.
- **Backend-enforced security**: per-launch session token, L0–L3 policy engine, human
  approvals bound to the exact action + parameters (single use, expiring), append-only
  hash-chained audit log, global emergency stop that kills process trees.
- **Controlled execution**: allowlisted executables only, argv only (never a shell),
  workspace containment, scrubbed environment, timeouts and output caps.
- **Ordered, replayable event stream** (WebSocket + REST replay).
- **Hardware discovery** scripts for choosing a local model runtime later.

## Repository layout

| Path | What |
|---|---|
| `backend/` | FastAPI backend (Python 3.12+, uv). Policy, approvals, audit, events, execution. |
| `apps/desktop/` | React + TypeScript + Three.js UI; `src-tauri/` is the Tauri 2 shell. |
| `packages/contracts/` | OpenAPI contract + generated TypeScript types (source: Pydantic). |
| `scripts/discovery/` | `discover.ps1` (Windows) and `discover.py` (any OS). Read-only. |
| `scripts/dev.sh` | Development launcher (backend + Vite with a throwaway token). |
| `infra/` | Docker Compose for PostgreSQL (bound to 127.0.0.1). |
| `docs/` | Architecture, security, threat model, requirements, decisions, status. |

## Step 1 on your Windows PC: discovery

```powershell
powershell -ExecutionPolicy Bypass -File scripts\discovery\discover.ps1 -Out .\discovery
```

It changes nothing and reports credential *names* only. Read `discovery\discovery-report.md`,
then share it. It decides the local model runtime (Phase 7).

## Development setup

Prerequisites: Git, Node 22 + pnpm 10, Python 3.12+ with [uv](https://docs.astral.sh/uv/),
PostgreSQL 16 (native or `infra/docker-compose.yml`), Rust (for the Tauri shell), and on
Windows the MSVC build tools + WebView2.

```bash
pnpm install
(cd backend && uv sync)

# Database: either export JARVIS_DATABASE_URL, or store it in the OS credential store:
(cd backend && uv run jarvis-backend secrets set database_url)
#   e.g. postgresql+psycopg://jarvis:<password>@127.0.0.1:5432/jarvis

export JARVIS_WORKSPACES=/path/to/a/project      # approved workspaces (comma-separated)
scripts/dev.sh                                    # backend + UI at http://127.0.0.1:1420
pnpm --filter @jarvis/desktop tauri dev           # or: the desktop shell
```

## Tests

```bash
cd backend && JARVIS_TEST_DATABASE_URL=postgresql+psycopg://...jarvis_test uv run pytest
pnpm lint && pnpm typecheck && pnpm test
E2E_DATABASE_URL=postgresql+psycopg://...jarvis_e2e pnpm --filter @jarvis/desktop e2e   # wipes that DB
(cd apps/desktop/src-tauri && cargo test)
```

## Licence

The `LICENSE` file is inherited from the previous contents of this repository (Microsoft's
JARVIS research project, MIT). Choosing this project's licence is an open owner decision; see
`docs/DECISIONS.md` (ADR-012).
