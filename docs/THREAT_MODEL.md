# Threat model (STRIDE)

Scope: Phases 0–2 as built. Assets: the user's PC and files, credentials, the audit trail, the
integrity of approvals. Trust boundaries: (1) webview ↔ backend, (2) backend ↔ child processes,
(3) backend ↔ database, (4) future: models/agents ↔ backend, iPhone ↔ host.

| # | Threat | Boundary | Mitigation (status) | Test evidence |
|---|---|---|---|---|
| S1 | Other local process or web page calls the API | 1 | Per-launch bearer token, loopback bind, origin check (built) | `test_requests_without_valid_token_are_rejected`, `test_foreign_origin_is_rejected` |
| S2 | Malicious site opens WS to localhost (CSWSH) | 1 | WS origin check + token subprotocol (built) | `test_websocket_rejects_bad_auth_and_origin` |
| S3 | Agent impersonates human to approve | 4 | Principal kind fixed server-side; agents never approve (built) | `test_agent_cannot_approve_even_its_own_request` |
| T1 | Approval reused for different/changed params | 4 | Hash-bound, single-use, atomic consume (built) | `test_approval_cannot_be_reused_for_different_params`, `test_l2_requires_approval_then_runs_once` |
| T2 | Audit log altered or deleted | 3 | DB trigger + hash chain verify (built); role separation (KI-002) | `test_audit_log_rejects_update_and_delete`, `test_audit_tampering_is_detected` |
| R1 | Action without record | all | Every decision path audited inside its transaction (built) | `test_every_action_is_audited_and_chain_verifies` |
| I1 | Secret leaks via logs/audit/events/output | all | Redaction + scrubbed child env (built) | `test_secrets_are_redacted_from_audit_and_logs`, `test_child_does_not_inherit_secrets` |
| I2 | Token leaks via URL/access logs | 1 | Token never in URL; uvicorn access log disabled (built) | code review |
| D1 | Runaway loop floods actions | 1 | Rate limit (built) | `test_rate_limit_blocks_runaway_loops` |
| D2 | Child produces unbounded output / hangs | 2 | Output cap with draining, timeout, tree kill (built) | `test_output_cap_truncates_without_deadlock`, `test_timeout_kills_whole_tree` |
| D3 | Slow WS consumer exhausts memory | 1 | Bounded per-subscriber queue, disconnect + replay (built) | code review (untested) |
| E1 | Shell/argument injection | 2 | No shell; allowlist + validators + git hardening (built) | `test_non_allowlisted_commands_are_denied`, `test_git_read_rejects_dangerous_args` |
| E2 | Workspace escape (`..`, symlink, UNC, drive) | 2 | realpath containment (built) | `test_workspace_escape_is_denied`, `test_symlink_workspace_escape_is_denied` |
| E3 | Malicious repo config runs code during git commands | 2 | exact flag allowlists; fsmonitor/hooks/pager/ext-diff/signature programs disabled; **filter drivers not covered** (KI-006) | `test_aud_h1_*` |
| E6 | Argument escapes (`--no-index`, abbreviated flags, absolute operands, pytest `-o`/`-c`/`--junitxml`) | 2 | Exact allowlists + relative operand containment (built) | `test_aud_h1_*`, `test_aud_h2_*` |
| E7 | Stop/cancel races process start-up | 2 | Post-registration re-check (built) | `test_aud_h3_*` |
| S4 | DNS rebinding | 1 | Loopback-only Host header (built) | `test_aud_l5_*` |
| S5 | Agent with the session token approves its own request | 4 | **Open, latent** (KI-003): no agents yet; children never receive the token | `test_child_does_not_inherit_secrets` |
| E4 | Process survives emergency stop | 2 | Process groups / Job Objects; unconfirmed kills reported (built; Windows untested) | `test_emergency_stop_kills_running_tree_and_blocks_new_work` |
| E5 | Agent resets emergency stop or changes policy | 4 | `mutates_policy` actions denied for agents (built) | `test_agent_cannot_reset_emergency_stop` |
| P1 | Prompt injection via web/docs/repo content | 4 | Planned: content tagged untrusted, models only request policy-checked actions (Phase 5–6) | not yet applicable |
| P2 | Memory poisoning | 4 | Planned: provenance + user-approved memory (Phase 8) | not yet applicable |
| N1 | iPhone/remote attack surface | — | Planned: private network + device pairing; no public exposure (Phase 11) | not yet applicable |
| C1 | Supply chain | build | Lockfiles, pip-audit, pnpm audit, gitleaks in CI (built) | CI |
