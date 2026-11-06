# Build status

Last verified: 2026-11-06, in a Linux cloud container (Ubuntu 24.04, 4 vCPU, 15.7 GB RAM, no GPU),
**not** on the Windows host PC. Classification (auditor scale): **CONDITIONAL**. There are no
open Critical findings. KI-002 and KI-003 (the Phase 6 blockers) are closed. The main open item
is Windows-native behaviour that has not been run on the target (KI-001).

## Phases

| Phase | Scope | Status |
|---|---|---|
| 0 Discovery | `discover.py`, `discover.ps1`, governance docs | **Done**, except that `discover.ps1` has been parsed and linted but not yet run on Windows |
| 1 Foundation | Monorepo, FastAPI, Postgres + Alembic, contracts, React/Three.js UI, Tauri shell, CI | **Done**, except the Windows Tauri bundle and release sidecar (KI-001, KI-004) |
| 2 Security core | Auth, L0–L3 policy, approvals, audit, controlled exec, emergency stop, secrets, agent credentials | **Done**. KI-002 and KI-003 closed; Windows-native parts untested (KI-001) |
| 3 Three-section interface | Navigation, drawers, honest empty states | **Partial**: shell and the exec/approval/audit/health journeys are done; agent content arrives with Phases 5–6 |
| 4–12 | Voice, providers, agents, memory, PC control, workflows, iPhone, validation | **Not started** |

## Verification evidence (final run)

| Check | Result |
|---|---|
| `ruff format --check` / `ruff check` | 51 files formatted / all checks passed |
| `mypy jarvis` (strict on security, exec, audit) | no issues in 37 files |
| Alembic upgrade → downgrade → upgrade → `check` | no drift |
| Backend `pytest` (real PostgreSQL 16) | **215 passed** (48 new for KI-002/KI-003, incl. a full journey as the restricted DB role) |
| `pip-audit` / `pnpm audit --prod` | no known vulnerabilities |
| Contracts regenerate identically | no drift |
| ESLint / `tsc -b` | clean |
| Frontend `vitest` | **21 passed** |
| Production build (`vite build`) | OK (chunk-size warning, KI-007) |
| Playwright e2e (real backend + DB + Chromium) | **8 passed** |
| `cargo test` / `cargo clippy -D warnings` (Linux) | 2 passed / clean |
| `discover.py` | report generated |
| `discover.ps1` | parser OK; PSScriptAnalyzer 0 findings. **Not executed on Windows** |

Screenshots of each major screen and journey are in `docs/evidence/`.

## Independent audit

Reviewer: a separate agent that did not write the code. Of 16 findings (4 High, 6 Medium, 6 Low), 11 are fixed with regression tests that reproduce the
auditor's scenario (`backend/tests/test_audit_findings.py`) and 1 is partially fixed (M1). The remaining 4 are
open and tracked: H4 (latent), M3, L2 and L3. Remediation also turned up two more issues of our own
(SELF-1 and SELF-2), both now fixed. Full register: `KNOWN_ISSUES.md`.

## Not tested (explicitly)

- Anything Windows-native: Job Object kill, Credential Manager, WebView2, the parent watchdog,
  the Tauri bundle and `discover.ps1`.
- Restore drill, disk pressure, a database restart during jobs, and load/performance.
- The slow WebSocket consumer path, and an accessibility pass with a screen reader.

## Next steps

1. **Owner:** run `scripts/discovery/discover.ps1` on the PC and share the report.
2. **Owner:** decide the project licence (ADR-012).
3. Run the dev stack on Windows and close KI-001 items with evidence; set up the
   `jarvis_runtime` database role there (RECOVERY_PLAN.md) so `audit_protection` is green.
4. Phase 4 (voice) and Phase 5 (provider adapters for ChatGPT and Claude).
