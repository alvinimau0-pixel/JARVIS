# Architecture

Status: covers what is built in Phases 0–2. Planned components are marked *(planned)*.

## Overview

```
 ┌──────────────── Windows PC (host) ─────────────────────────────────────────┐
 │                                                                            │
 │  Tauri 2 shell (Rust)                                                      │
 │   ├─ generates per-launch session token (32 random bytes, memory only)      │
 │   ├─ picks a free 127.0.0.1 port, spawns backend, kills it on exit          │
 │   └─ webview ── IPC get_session ──► {base_url, token}                        │
 │        │  React + TS + Three.js UI (3 sections + drawers)                   │
 │        │  HTTP  Authorization: Bearer <token>                               │
 │        │  WS    subprotocols [jarvis.v1, auth.<token>]                      │
 │        ▼                                                                    │
 │  FastAPI backend (127.0.0.1 only)                                           │
 │   ├─ AuthMiddleware (token, origin) · RateLimit · CORS                      │
 │   ├─ ActionService ─ the ONLY execution path                                │
 │   │    PolicyEngine (L0–L3) → Approvals (hash-bound) → Runner               │
 │   ├─ EventBus (persist → seq → broadcast; replay since_seq)                 │
 │   ├─ Audit log (append-only, hash chain, DB trigger)                        │
 │   ├─ EmergencyLatch (persisted) + ProcessRegistry (tree kill)               │
 │   └─ SecretStore → Windows Credential Manager (keyring)                     │
 │        │                                                                    │
 │        ▼                                                                    │
 │  PostgreSQL 16 (127.0.0.1)                                                  │
 └────────────────────────────────────────────────────────────────────────────┘
   iPhone companion (planned, Phase 11): PWA over an authenticated private
   network; never direct access to DB, model runtime or execution service.
```

## Backend modules (`backend/jarvis/`)

| Module | Responsibility |
|---|---|
| `core/config.py` | Settings from `JARVIS_*` env; DB URL fallback to the OS credential store; loopback-only bind. |
| `core/redaction.py` | Redacts secrets from logs, audit records, events and child output. |
| `api/security.py` | Bearer-token auth, origin enforcement, rate limiting, WS authentication. |
| `api/routes.py` | Versioned `/api/v1` routes. No route runs a raw command. |
| `api/schemas.py` | Pydantic contracts (source of truth for `packages/contracts`). |
| `security/policy.py` | Action registry and L0–L3 decisions (allow / require approval / deny). |
| `security/approvals.py` | Create / decide / atomically consume approvals bound to `sha256(action+params)`. |
| `security/paths.py` | Workspace containment (realpath, no absolute/UNC/drive paths, no symlink escape). |
| `security/emergency.py` | Persisted emergency-stop latch. |
| `exec/allowlist.py` | Allowlisted executables, per-executable argument validators, git hardening. |
| `exec/runner.py` | argv-only subprocesses: scrubbed env, timeout, output cap, cancellation. |
| `exec/proctree.py` | Process-tree containment: POSIX process groups; Windows Job Objects. |
| `tasks/service.py` | Lifecycle: policy → approval → task/job → run → events + audit; cancel; stop; recovery. |
| `events/bus.py` | Persist-then-broadcast ordered events; replay; slow-consumer disconnect. |
| `audit/log.py` | Hash-chained append and verification. |
| `secrets/store.py` | OS credential store wrapper (`keyring`). |

## Action lifecycle

1. `POST /api/v1/actions {action, params, reason, approval_id?}`
2. `PolicyEngine.evaluate(principal, action, params, emergency_latched)`
   - unknown action / invalid params / not allowlisted / workspace escape → **DENY** (audited, `action.denied` event)
   - agent principal + policy-mutating action → **DENY**
   - executing action while emergency stop latched → **DENY** (HTTP 423)
   - level = max(action base level, executable rule level)
   - L0/L1 → **ALLOW**; L2/L3 → **REQUIRE_APPROVAL**
3. Approval path: first call creates a pending approval (`approval.required`). A human approves
   via `/approvals/{id}/approve`. The second call with `approval_id` atomically consumes it only if
   the status is `approved`, it has not expired, it has not been used, and the hash matches.
4. Execution creates a task and job, audits, emits `task.created`, then runs in the background:
   `job.started` → `job.completed | job.failed | job.cancelled` → `task.*`.
5. Results are stored on the job (and on the approval, when there is one) and audited.

## Visual state

The UI derives its visual state from backend facts only (`apps/desktop/src/state/visual.ts`).
Wired today: IDLE, EXECUTING, WAITING_APPROVAL, COMPLETED (transient), ERROR, OFFLINE. The
remaining constitution states are defined in the type but not wired until their phases ship.

## Deliberate exclusions

OmniRoute is excluded. LiteLLM is not used (ADR-004). n8n, Remotion and JEV/TypeSafe are not part
of the current build (ADR-006 to ADR-008).
