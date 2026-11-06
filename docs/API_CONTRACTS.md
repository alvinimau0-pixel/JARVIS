# API contracts — v1

Machine-readable source: `packages/contracts/openapi.json` (generated from
`backend/jarvis/api/schemas.py`). TypeScript types: `packages/contracts/src`. To change a
contract: edit the Pydantic model, run `pnpm contracts:gen`, update this page, commit both.

## Conventions
- Base: `http://127.0.0.1:<port>/api/v1`. Auth: `Authorization: Bearer <session token>`.
- Errors: `{"error": {"code": "<machine_code>", "message": "<human text>"}}`.
- Times are ISO-8601 UTC. IDs are UUIDs except event `seq` and audit `id` (integers).

## Endpoints
| Method | Path | Purpose | Notes |
|---|---|---|---|
| GET | `/health/live` | Liveness | Public; returns `{"status":"ok"}` only |
| GET | `/health` | Real checks: database, migrations, event bus, emergency stop, workspaces | `HealthOut` |
| GET | `/catalog` | Actions (with JSON Schemas), allowlisted executables with levels, workspace names | `CatalogOut` |
| POST | `/actions` | Submit an action | `ActionRequest` → `ActionResponse` (see below) |
| GET | `/approvals?status=` | List approvals | `ApprovalOut[]` |
| POST | `/approvals/{id}/approve` · `/deny` | Human decision | 403 if not human, 409 if not pending, 410 if expired |
| GET | `/tasks?limit=` | Recent tasks with jobs | `TaskOut[]` |
| GET | `/jobs/{id}` | Job status, exit code, redacted output | `JobOut` |
| POST | `/jobs/{id}/cancel` | Kill the job's process tree | `{running, stopped, detail}` |
| GET | `/system/state` | Emergency latch, active job count | `SystemStateOut` |
| POST | `/system/emergency-stop` | Latch + kill all + report | `EmergencyStopReport`; not rate limited |
| GET | `/audit?limit=` · `/audit/verify` · `/audit/count` | Audit log, chain verification | |
| GET | `/events?since_seq=&limit=` | Replay | `EventOut[]` ordered by `seq` |
| WS | `/ws?since_seq=` | Live events | Subprotocols `jarvis.v1`, `auth.<token>`; close 4401 on auth failure, 4408 if lagging |

### `POST /actions` outcomes
| HTTP | `status` / `error.code` | Meaning |
|---|---|---|
| 202 | `accepted` | Job started; follow `job_id` events |
| 202 | `approval_required` | `approval` returned; human must approve, then resubmit the same action+params with `approval_id` |
| 200 | `completed` | Synchronous action finished (e.g. `system.emergency_reset`) |
| 403 | `invalid_params`, `not_allowlisted`, `workspace_violation`, `agent_cannot_modify_policy`, `approval_action_mismatch`, `approval_not_approved` | Denied (audited) |
| 404 | `unknown_action`, `approval_not_found` | |
| 409 | `approval_already_used` | Replay refused |
| 410 | `approval_expired` | |
| 423 | `emergency_stop_active` | Execution blocked |
| 429 | `rate_limited` | |

### Actions (v1)
- `exec.run` `{executable, args[], workspace, cwd=".", timeout_s?}` — level comes from the
  executable rule: `git` (read-only subcommands) L0, `python` (`-m pytest` only) L1, `git-push` L2.
- `system.emergency_reset` `{}` — L3, human only.

## Events
`EventOut {id, seq, type, source, task_id?, job_id?, ts, payload}`. Clients order and de-duplicate
by `seq`. Types: `task.created|completed|failed|cancelled`, `job.started|completed|failed|cancelled`,
`approval.required|granted|denied`, `action.denied`, `system.emergency_stop|emergency_reset|recovered`.

Planned (not emitted yet): `task.planned`, `agent.assigned|started|progress|completed|failed`,
`system.offline`. These will be added with the agent phases.
