# Security

Reporting: this is a personal project; report issues to the repository owner privately.

## Model
- **Backend is the security boundary.** UI controls are convenience only.
- **Loopback only.** The backend refuses to bind to non-loopback addresses (config validator).
- **Authentication.** Every `/api/*` request needs `Authorization: Bearer <session token>`
  (constant-time compare). WS needs subprotocols `jarvis.v1` + `auth.<token>`. Only
  `/api/v1/health/live` is public and returns `{"status":"ok"}` only.
- **Origin enforcement.** Requests or WS handshakes carrying an `Origin` not in the allowlist are
  rejected (403 / close 4401). CORS allows only the configured origins.
- **Host check.** Only loopback `Host` headers are accepted (DNS-rebinding defence).
- **Rate limiting.** Mutating requests and audit verification are limited per client (default
  120/min). The emergency stop is exempt. At most `JARVIS_EXEC_MAX_CONCURRENT_JOBS` (default 4)
  jobs run at once; more are refused with 429.
- **Lifetime.** The backend watches the desktop shell's PID and shuts down (killing its children)
  if the shell disappears.

## Permission levels (enforced in `jarvis/security/policy.py`)
| Level | Meaning | Decision |
|---|---|---|
| L0 READ | inspect inside approved workspaces | allow |
| L1 ROUTINE | edit/test inside approved workspaces | allow |
| L2 SENSITIVE | installs, publishing, push, external changes | human approval |
| L3 CRITICAL | deletion, credentials, security policy, money | human approval, always |

Agents (`PrincipalKind.AGENT`) can never approve anything, and can never run policy-mutating
actions (e.g. `system.emergency_reset`). Only `PrincipalKind.HUMAN` decides approvals.
**Open (KI-003, latent):** today every holder of the session token is treated as the human
operator. No agent exists yet and child processes never receive the token, but transport-level
agent credentials must exist before Phase 6 ships.

## Approvals
Bound to `sha256(action + canonical params)`, single use, 10-minute expiry, consumed atomically.
Any parameter change ⇒ `approval_action_mismatch`. Result is recorded on the approval.

## Controlled execution
- Executable allowlist resolved to absolute paths at startup; argv lists only, never a shell.
- Per-executable argument validators with **exact** flag allowlists per git subcommand and for
  pytest (abbreviated options are therefore rejected), and positional operands that must be
  workspace-relative (no absolute, drive, home or `..` components). Push takes only plain
  remote/branch names.
- Git hardening flags disable hooks, fsmonitor, pagers, external diff tools and signature
  verification programs. Repository filter drivers are **not** covered (KI-006).
- Working directory resolved with realpath and contained in an approved workspace; absolute,
  drive, UNC, rooted and NUL paths rejected; symlink escapes rejected.
- Environment scrubbed to a minimal allowlist (no API keys or tokens inherited).
- Timeout (capped), output cap (drained, never blocks), process-tree kill.

## Emergency stop
`POST /api/v1/system/emergency-stop`: blocks execution in memory first, kills every tracked
process tree (never waiting on the database), then persists the latch (survives restart), expires
outstanding approvals, cancels queued jobs and audits. It reports any process **not** confirmed
stopped and whether the stop could be persisted. Reset is an L3 action requiring human approval;
the in-memory latch is released only after the reset commits.

## Audit
Append-only (DB trigger) + hash chain; `/api/v1/audit/verify` detects modification. Denials,
approval requests/decisions, executions, results, cancellations, stops and recovery are recorded.
Secrets are redacted before writing.

## Secrets
- OS credential store via `keyring` (`jarvis-backend secrets set database_url`).
- Never in source, config, browser storage, logs, audit, events or child environments.
- Redaction covers common key formats, bearer tokens, `password=`-style pairs, DB URLs, PEM keys
  and any registered runtime secret (the session token, the DB URL).
- CI uses passwordless, runner-local throwaway Postgres; gitleaks scans history.

## Untrusted input
Web pages, documents, repository files and tool output are data, never policy. Today no model
consumes such content yet; the defences that already apply are structural: models will only
ever be able to *request* named actions that pass the same policy engine and approvals.

See `THREAT_MODEL.md` for threats and `KNOWN_ISSUES.md` for open gaps.
