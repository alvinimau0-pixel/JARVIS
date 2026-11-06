# Security

Reporting: this is a personal project; report issues to the repository owner privately.

## Model
- **Backend is the security boundary.** UI controls are convenience only.
- **Loopback only.** The backend refuses to bind to non-loopback addresses (config validator).
- **Authentication.** Every `/api/*` request needs `Authorization: Bearer <token>`
  (constant-time compare). Two kinds of token exist:
  - the **operator session token**: generated per launch by the desktop shell, handed only to
    the webview over Tauri IPC, never written to disk or given to child processes. It is the
    human-presence credential and the only one that authenticates as `PrincipalKind.HUMAN`;
  - **agent tokens** (`jat_…`): issued per agent by the operator (`POST /agents/credentials`),
    held by the backend only as SHA-256 digests, revocable, and all revoked by the emergency
    stop. They authenticate as `PrincipalKind.AGENT` and may call only `POST /actions`,
    `GET /jobs/{id}`, `GET /catalog` and `GET /health`; every other route answers 403
    `agent_forbidden` (`jarvis/security/agents.py`, `AGENT_ROUTES`).

  WS needs subprotocols `jarvis.v1` + `auth.<operator token>`; agent tokens are refused. Only
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
actions (e.g. `system.emergency_reset`). Only `PrincipalKind.HUMAN` decides approvals. This is
enforced three times: agent tokens cannot reach the approval, emergency and credential routes
(transport), those routes require a human principal (`Human` dependency), and
`approvals.decide` refuses non-humans (service). Agents cannot obtain the human credential:
child processes get an allowlisted environment, so neither token kind is inherited.

## Approvals
Bound to `sha256(action + canonical params)`, single use, 10-minute expiry, consumed atomically.
Any parameter change ⇒ `approval_action_mismatch`. An approval can be spent only by the principal
that requested it (one agent cannot use another's, nor the operator an agent's)
⇒ `approval_requester_mismatch`. Result is recorded on the approval.

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
`POST /api/v1/system/emergency-stop` (operator only): blocks execution in memory first, revokes
every agent credential, kills every tracked process tree (never waiting on the database), then persists the latch (survives restart), expires
outstanding approvals, cancels queued jobs and audits. It reports any process **not** confirmed
stopped and whether the stop could be persisted. Reset is an L3 action requiring human approval;
the in-memory latch is released only after the reset commits.

## Audit
Four layers (`jarvis/audit/`, migrations 0001–0002):
1. **Keyed chain.** Each entry's hash is HMAC-SHA256, under the audit key, over the previous
   hash and the entry's canonical content. Without the key, nobody (a database superuser
   included) can edit, insert or reorder entries and produce a chain that verifies.
2. **Insert-only runtime role.** The backend should connect as a member of `jarvis_app`, which
   may only `SELECT`/`INSERT` audit rows and owns nothing, so it cannot update, delete,
   truncate, or disable/drop the protecting triggers. Migrations run as the owner. The Health
   drawer's `audit_protection` check is red while the backend connects as owner/superuser.
3. **Triggers** reject `UPDATE`/`DELETE`/`TRUNCATE` for every role until an owner disables them.
4. **External anchor.** The chain head `{id, hash}` is appended to
   `<data_dir>/audit-anchor.jsonl` at startup, every minute when it moved, and at shutdown.
   `/audit/verify` fails if the latest anchored entry is missing or changed, which catches
   entries deleted from the end of the chain (a keyed chain alone cannot).

Residual risk: someone controlling the database owner role **and** the anchor file can still
truncate the newest entries undetected; off-machine anchoring is planned with Phase 11. Losing
the audit key makes the existing chain unverifiable (it is not recoverable from the database).

Denials, approval requests/decisions, executions, results, cancellations, stops, agent
credential issue/revoke and recovery are recorded. Secrets are redacted before writing.

## Secrets
- OS credential store via `keyring` (`jarvis-backend secrets set database_url`). The audit HMAC
  key (`audit_hmac_key`) is generated there on first start; `JARVIS_AUDIT_KEY` overrides it
  (tests, CI, headless dev). Without a key the backend refuses to start.
- Never in source, config, browser storage, logs, audit, events or child environments.
- Redaction covers common key formats, bearer tokens, `password=`-style pairs, DB URLs, PEM keys
  agent tokens (`jat_…`) and any registered runtime secret (session token, agent tokens, audit
  key, DB URL).
- CI uses passwordless, runner-local throwaway Postgres; gitleaks scans history.

## Untrusted input
Web pages, documents, repository files and tool output are data, never policy. Today no model
consumes such content yet; the defences that already apply are structural: models will only
ever be able to *request* named actions that pass the same policy engine and approvals.

See `THREAT_MODEL.md` for threats and `KNOWN_ISSUES.md` for open gaps.
