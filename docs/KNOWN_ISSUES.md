# Known issues register

Severity: Critical · High · Medium · Low. "Latent" means the vulnerable path cannot be reached by
any component that exists yet, but it must be closed before the named phase ships.

## Independent audit (2026-11-06), Phases 0–2

The audit was done by a separate reviewer agent that did not write the code. Findings, outcome and evidence:

| ID | Sev | Finding | Status | Evidence |
|---|---|---|---|---|
| AUD-H1 | High | `git diff --no-index /etc/passwd …` read files outside the workspace at L0; abbreviated flags (`--ext-d`) bypassed prefix checks; `--show-signature` could run `gpg.program` | **Fixed**: exact per-subcommand flag allowlists, workspace-relative operands only, `log.showSignature=false` | `test_audit_findings.py::test_aud_h1_*` |
| AUD-H2 | High | pytest args escaped containment (`/abs/path`, `-o addopts=-p…`, `-c /x.ini`, `--junitxml=/x`) | **Fixed**: flag allowlist + relative operands. Running tests still executes workspace code by design (L1 "test in approved workspace") | `test_aud_h2_*` |
| AUD-H3 | High | Stop/cancel issued while a process was being created missed it | **Fixed**: re-check after registration, immediate tree kill | `test_aud_h3_abort_after_registration_kills_process` |
| AUD-H4 | High (latent) | Every token holder is the human operator; an agent process holding the token could approve its own L2/L3 request | **Fixed** (KI-003): agents get separate, revocable, route-restricted tokens mapped to `Principal.agent`; approval, emergency and credential routes are human-only at transport, handler and service level; approvals are bound to their requester; the emergency stop revokes all agent tokens | `test_ki002_ki003.py::test_agent_*`, `test_approval_can_only_be_spent_by_its_requester`, `test_emergency_stop_revokes_every_agent_credential` |
| AUD-M1 | Medium | `git push` approval shows remote *name*, not resolved URL; repo-configured `credential.helper`/`sshCommand` still apply | **Partially fixed**: branch mutations now impossible at L0; push operands restricted to plain names. **Open:** show + hash the resolved remote URL in the approval (Phase 6) | `test_aud_h1_git_push_operands` |
| AUD-M2 | Medium | Denial audit entries for failed approval use/decision were rolled back | **Fixed**: written in their own transaction | `test_aud_m2_*` |
| AUD-M3 | Medium | App role owns `audit_log` and can drop triggers; unkeyed hash chain can be recomputed; tail deletion undetectable | **Fixed** (KI-002): HMAC-keyed chain (key in OS credential store), insert-only `jarvis_app` runtime role (migration 0002), external head anchor. Residual risk noted in SECURITY.md | `test_ki002_ki003.py::test_forged_entry_*`, `test_runtime_role_*`, `test_truncated_tail_is_detected` |
| AUD-M4 | Medium | On Windows `child.kill()` reaches only `uv`; backend could outlive the app | **Fixed (untested on target)**: backend watches `JARVIS_PARENT_PID` and shuts down | `test_aud_m4_*` (Linux) |
| AUD-M5 | Medium | Emergency latch cleared in memory before the reset committed | **Fixed**: released in memory only after commit | `test_aud_m5_failed_reset_keeps_execution_blocked` |
| AUD-M6 | Medium | No cap on concurrent jobs; `audit/verify` unthrottled | **Fixed**: `JARVIS_EXEC_MAX_CONCURRENT_JOBS` (default 4) → 429; verify rate-limited | `test_aud_m6_concurrent_job_limit` |
| AUD-L1 | Low | Redaction missed Stripe/Google/STS keys, JWTs, `--password X`, URL credentials, tracebacks | **Fixed** (approval `params` are stored verbatim by design: they are what the human approves and what is hashed) | `test_aud_l1_*` |
| AUD-L2 | Low | Port chosen by the shell could be taken by another process before the backend binds | **Open** (KI-009) | — |
| AUD-L3 | Low | CSP allows `style-src 'unsafe-inline'` and `connect-src 127.0.0.1:*` | **Open** (KI-010) | — |
| AUD-L4 | Low | Pending/approved approvals survived an emergency stop | **Fixed**: expired on stop | `test_aud_l4_*` |
| AUD-L5 | Low | No Host header check (DNS rebinding) | **Fixed**: loopback-only `TrustedHostMiddleware` | `test_aud_l5_*` |
| AUD-L6 | Low | Workspaces addressed by basename could collide | **Fixed**: duplicate names rejected at startup | `test_aud_l6_*` |

Found during the remediation itself:

| ID | Sev | Finding | Status | Evidence |
|---|---|---|---|---|
| SELF-1 | High | Emergency stop wrote to the DB **before** killing processes; with the DB down nothing would be killed | **Fixed**: kill first (in memory), persist/audit best-effort, report `persisted:false` | `test_emergency_stop_kills_even_when_database_is_unavailable` |
| SELF-2 | Medium | Allowlist resolved venv `python3` symlink to the base interpreter (lost the venv) | **Fixed** | `test_default_allowlist_keeps_virtualenv_interpreter`; e2e emergency-stop journey |

## Open register

| ID | Sev | Issue | Plan |
|---|---|---|---|
| KI-001 | High | Windows-native behaviour **untested on target**: Job Object tree kill, Credential Manager, `discover.ps1` execution, Tauri Windows bundle, parent watchdog on Windows | Run on the PC; CI has a Windows job for the Rust shell |
| KI-002 | — | **Closed 2026-11-06.** Keyed chain, insert-only runtime role, external anchor (AUD-M3). Remaining: the owner must actually connect the backend as `jarvis_runtime` (RECOVERY_PLAN.md); Health shows `audit_protection` red until then. Off-machine anchoring waits for Phase 11; audit-key rotation is not supported | `test_ki002_ki003.py` |
| KI-003 | — | **Closed 2026-11-06.** Separate agent credentials and human-only routes (AUD-H4). Phase 6 must issue each spawned agent its own credential and pass it through the scrubbed environment explicitly | `test_ki002_ki003.py` |
| KI-004 | Medium | No packaged backend for release builds: the Tauri shell runs the backend from the repo with `uv` (dev-grade) | Build a sidecar (e.g. PyInstaller) or ship an embedded Python; sign it |
| KI-005 | Low | Orphaned children from a *crashed* backend are reported (PIDs) but not killed on restart (PID reuse risk) | Persist job-object/process-group identity, verify before kill |
| KI-006 | Medium | Untrusted repos: git filter drivers (`.gitattributes` + repo config) can still run during `git status`/`diff` | Only approve trusted workspaces; future: run git with `GIT_CONFIG_GLOBAL`/safe config overlay or in a sandbox |
| KI-007 | Low | three.js bundle is ~600 kB (chunk-size warning) | Code-split the scene if startup time matters |
| KI-008 | Medium | Backup/restore drill not executed | Add an automated restore test |
| KI-009 | Low | Port race between shell and backend (AUD-L2) | Backend binds port 0 and reports its port to the shell |
| KI-010 | Low | CSP `unsafe-inline` styles and wildcard loopback port (AUD-L3) | Remove inline style attributes; fix the backend port per install |
| KI-011 | Low | Visual states for voice/agents (LISTENING, THINKING, …) defined but not wired | Wire with Phases 4–6 |
| KI-012 | Info | Licence of this repository is undecided (inherited MIT file) | Owner decision (ADR-012) |
| KI-013 | Low | Slow-consumer WebSocket disconnect path has no automated test | Add a test with a non-reading client |
| KI-014 | Low | `openapi-typescript` declares a peer of TypeScript 5; repo uses TypeScript 6.0.3 (works, warning on install) | Track upstream |
