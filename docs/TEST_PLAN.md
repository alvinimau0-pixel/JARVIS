# Test plan

| Layer | Tool | Location | Runs in CI | Count (this build) |
|---|---|---|---|---|
| Backend unit (policy, paths, args, hashing, redaction, config) | pytest | `backend/tests/test_unit_security.py`, `test_config.py` | yes | 54 |
| Audit-finding regressions (each reproduces an auditor scenario) | pytest | `backend/tests/test_audit_findings.py` | yes | 55 |
| Process runner (real child processes, tree kill) | pytest | `backend/tests/test_runner.py` | yes (Linux) | 8 |
| API integration (real Postgres) | pytest + TestClient | `backend/tests/test_api.py` | yes | 10 |
| Security: demonstrated blocked actions | pytest | `backend/tests/test_security_api.py` | yes | 40 |
| Migrations up/down/up + model drift | alembic | CI step | yes | — |
| Frontend unit (event adapter, visual state, argv, 3-section rule) | vitest | `apps/desktop/src/**/*.test.*` | yes | 21 |
| End-to-end user journeys (real backend + DB + browser) | Playwright | `apps/desktop/e2e/` | yes | 8 |
| Tauri shell | cargo test + clippy | `apps/desktop/src-tauri` | yes (Windows runner) | 2 |
| Supply chain | pip-audit, pnpm audit, gitleaks | CI | yes | — |

Rules: security features count as done only with a test that demonstrates the blocked action.
Tests are never deleted or skipped to get green builds.

## Not covered yet (tracked in KNOWN_ISSUES)
- Windows-native execution of process-tree kill, Credential Manager, Tauri bundle, `discover.ps1`.
- Slow-consumer WS disconnect, rate limiting under concurrency, load/performance tests.
- Backup/restore drill, disk-pressure and DB-restart reliability tests.
- Accessibility audit with assistive technology (keyboard/ARIA basics only so far).
