# Traceability matrix

Requirement → implementation → tests → evidence. Test names refer to `backend/tests/`,
`apps/desktop/src/**/*.test.ts(x)` and `apps/desktop/e2e/journeys.spec.ts`.

| REQ | Implementation | Tests | Evidence |
|---|---|---|---|
| 001 | `apps/desktop/src/app/sections.ts`, `App.tsx` | `App.test.tsx` (3 entries); e2e "three sections navigate…", "iPhone viewport…" | `docs/evidence/01–03,10*.png` |
| 002 | `sections/Sections.tsx` (not-configured states), `state/visual.ts` | `visual.test.ts` "is IDLE when connected with nothing happening"; e2e "L2 … runs" shows a real failed push | `07-approved-push-failed-honestly.png` |
| 003 | `scripts/discovery/discover.{py,ps1}` | ran `discover.py` in container; `discover.ps1` parsed + PSScriptAnalyzer clean | BUILD_STATUS |
| 010 | `core/config.py` (`_loopback_only`), `api/security.py` | `test_backend_refuses_non_loopback_bind`, `test_requests_without_valid_token_are_rejected` | pytest |
| 011 | `api/schemas.py`, `scripts/export_contracts.py`, `packages/contracts` | CI drift check | CI |
| 012 | `events/bus.py`, `api/routes.py` (ws), `src/events/adapter.ts` | `test_events_are_ordered…`, `test_websocket_streams_live_events_in_order`, `test_websocket_replays_missed_events`, `adapter.test.ts` (dedupe, gap repair, reconnect) | pytest, vitest |
| 013 | `migrations/versions/0001_foundation.py` | up/down/up + `alembic check` (CI and local) | BUILD_STATUS |
| 014 | `routes.health` | `test_health_reports_real_checks` | pytest |
| 020 | `security/policy.py` | `test_policy_levels`, `test_policy_denials` | pytest |
| 021 | `security/approvals.py`, `tasks/service.py` | `test_l2_requires_approval_then_runs_once`, `test_approval_cannot_be_reused_for_different_params`, `test_expired_approval_is_refused`, `test_l3_without_approval_does_not_execute`; e2e approval flow | pytest, `06-approval-pending.png` |
| 022 | `approvals.decide`, `policy.evaluate` (`mutates_policy`) | `test_agent_cannot_approve_even_its_own_request`, `test_agent_cannot_reset_emergency_stop`, `test_agent_cannot_touch_policy` | pytest |
| 023 | `db/models.Approval` | `test_l2_requires_approval_then_runs_once` (execution_result) | pytest |
| 024 | `exec/allowlist.py` | `test_aud_h1_*`, `test_aud_h2_*`, `test_git_read_rejects_dangerous_args`, `test_non_allowlisted_commands_are_denied`, `test_raw_shell_param_is_rejected`, `test_no_raw_command_endpoint_exists`; e2e "disallowed command is denied" | pytest, e2e |
| 025 | `security/paths.py` | `test_paths_escaping_workspace_are_rejected`, `test_symlink_escape_is_rejected`, `test_workspace_escape_is_denied`, `test_unapproved_workspace_is_denied` | pytest |
| 026 | `exec/runner.py`, `exec/proctree.py` | `test_timeout_kills_whole_tree`, `test_output_cap_truncates_without_deadlock`, `test_orphaned_grandchild_is_cleaned_up` | pytest (Linux) |
| 027 | `tasks/service.emergency_stop`, `security/emergency.py` | `test_emergency_stop_kills_even_when_database_is_unavailable`, `test_aud_h3_*`, `test_aud_m5_*`, `test_aud_l4_*`, `test_emergency_stop_kills_running_tree_and_blocks_new_work`, `test_emergency_stop_survives_restart`; e2e emergency stop | `09-emergency-stop.png` |
| 028 | `service.cancel_job` | `test_cancel_kills_tree`, `test_cancel_single_job` | pytest |
| 029 | `audit/log.py`, migration trigger | `test_aud_m2_*`, `test_audit_log_rejects_update_and_delete`, `test_audit_tampering_is_detected`, `test_every_action_is_audited_and_chain_verifies` | pytest |
| 030 | `core/redaction.py`, `runner.scrubbed_env` | redaction unit tests, `test_secrets_are_redacted_from_audit_and_logs`, `test_child_does_not_inherit_secrets`, `test_secrets_in_output_are_redacted` | pytest |
| 031 | `secrets/store.py`, `config.load_settings`, `jarvis-backend secrets` | `test_config.py` (MemoryStore) | pytest |
| 032 | `RateLimitMiddleware`, `AuthMiddleware` origin, `TrustedHostMiddleware`, concurrency cap | `test_rate_limit_blocks_runaway_loops`, `test_foreign_origin_is_rejected`, `test_aud_l5_*`, `test_aud_m6_*` | pytest |
| 033 | `.github/workflows/ci.yml` | pip-audit / pnpm audit run locally: no known vulnerabilities | BUILD_STATUS |
| 040 | `scene/Core.tsx`, `scene/palette.ts` | e2e state assertions (IDLE, EXECUTING, WAITING APPROVAL, ERROR, OFFLINE) | `01,08,09,11*.png` |
