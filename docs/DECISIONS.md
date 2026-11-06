# Decision log (ADRs)

Each entry: context → decision → consequences. Superseded decisions stay, marked.

## ADR-001 Desktop shell: Tauri 2
Small footprint, Rust host process, WebView2 on Windows, explicit capability model. The webview
gets **no** shell, fs or process plugins; one IPC command (`get_session`). Electron rejected:
heavier, larger attack surface by default.

## ADR-002 Backend: Python + FastAPI, PostgreSQL 16, SQLAlchemy 2 (async) + Alembic
Python has the strongest AI SDK ecosystem. Postgres gives transactions, JSONB, row locks
(needed for single-use approvals), triggers (append-only audit) and later pgvector.
Driver: psycopg 3 (one driver for async app and sync migrations).

## ADR-003 Contracts: Pydantic is the source of truth
`backend/scripts/export_contracts.py` writes OpenAPI; `openapi-typescript` generates TS types into
`packages/contracts`. CI fails on drift. The UI never hand-writes API types.

## ADR-004 No LiteLLM, no OmniRoute (yet / ever)
OmniRoute is excluded by the constitution. LiteLLM is not adopted: a clean provider abstraction
with direct adapters is planned for Phase 5; a gateway is reconsidered only with measured need.

## ADR-005 Single execution path through a policy engine
All side effects are named actions evaluated by `PolicyEngine`. There is deliberately no
"run command" endpoint. Executables are allowlisted with per-executable argument validators,
and each executable carries its own permission level (git read = L0, pytest = L1, git push = L2).

## ADR-006 n8n
Out of scope until Phase 10. If adopted it is an external automation runner invoked through
policy-checked actions; it never becomes the commander.

## ADR-007 Remotion
Only for rendered cinematic compositions (not the live UI, which is Three.js). Its licence
requires a company licence for some commercial/team use. **Re-verify the current licence before
adoption.** Not a dependency today.

## ADR-008 JEV/TypeSafe
Not adopted. May be evaluated later as a bounded validation layer, never as the agent runtime
or security authority.

## ADR-009 Session token over Tauri IPC (not cookies, not browser storage)
The shell generates 32 random bytes per launch, passes them to the backend via environment and
to the webview via IPC; the UI keeps it in memory. WS auth uses the `auth.<token>` subprotocol
because browsers cannot set WS headers and query strings end up in logs. Dev mode uses a
throwaway per-run token injected by `scripts/dev.sh` (DEV builds only).

## ADR-010 Approvals bound to a canonical hash
`sha256(canonical_json({action, params}))`, consumed with a single conditional `UPDATE … RETURNING`
(status=approved, unconsumed, unexpired, same hash). Prevents replay, parameter swapping and
races between two consumers.

## ADR-011 Append-only audit with hash chain
DB trigger rejects UPDATE/DELETE/TRUNCATE; each entry hashes the previous entry's hash, so even a
table owner who disables the trigger is detected by `/audit/verify`. Separate DB roles
(migration owner vs app) are planned (KI-002).

## ADR-012 Licence: owner decision pending
The repository previously held Microsoft's JARVIS research code (MIT). That code was removed with
the owner's approval (history retained). The existing `LICENSE` is untouched; the owner must
choose this project's licence.

## ADR-013 Local model runtime: deferred
No runtime is chosen until the Windows discovery report (`scripts/discovery/discover.ps1`) is
available. Do not assume a high-end GPU.

## ADR-014 Development container ≠ host
This build was produced in a Linux cloud container. Windows-specific code (Job Objects,
Credential Manager, Tauri Windows bundle, `discover.ps1` execution) is written and statically
checked but labelled **UNTESTED ON TARGET** until run on the PC.
