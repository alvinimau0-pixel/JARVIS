# Requirements

Derived from the JARVIS Master Prompt Pack. Status values: **Done** (implemented, integrated,
tested; evidence in TRACEABILITY.md) · **Partial** · **Untested on target** · **Open** (not built).

| ID | Requirement | Phase | Status |
|---|---|---|---|
| REQ-001 | Exactly three primary sections: CLAUDE, CODEX, BRAIN & WORKFLOW; everything else in drawers/overlays | 3 | Done |
| REQ-002 | No fake data, progress, activity or success; honest empty/not-configured states | all | Done (for built scope) |
| REQ-003 | Hardware/environment discovery before choosing models or heavy installs | 0 | Partial: scripts done; Windows run pending |
| REQ-004 | Governance documents maintained (11 docs + traceability) | 0 | Done |
| REQ-010 | Backend binds to loopback; every request authenticated | 1–2 | Done |
| REQ-011 | Typed, versioned API and event contracts; frontend uses generated types | 1 | Done |
| REQ-012 | Event stream with ids, timestamps, task ids, source; handles duplicate/out-of-order/missed events | 1 | Done |
| REQ-013 | Database migrations with up/down; referential integrity | 1 | Done |
| REQ-014 | Health endpoint with real checks | 1 | Done |
| REQ-020 | Permission levels L0–L3 enforced in backend | 2 | Done |
| REQ-021 | L2/L3 require human approval bound to exact action + params | 2 | Done |
| REQ-022 | Agents cannot approve, change policy/permissions, or reset the emergency stop | 2 | Partial: enforced for agent principals; transport-level agent credentials open (KI-003, blocks Phase 6) |
| REQ-023 | Approval record: action, requester, target, level, reason, timestamps, approver, decision, result | 2 | Done |
| REQ-024 | Command allowlist, argument validation, no arbitrary shell | 2 | Done (git filter drivers: KI-006) |
| REQ-025 | Workspace isolation; escapes blocked | 2 | Done |
| REQ-026 | Timeouts, output limits, process-tree tracking and kill | 2 | Done (POSIX) · Untested on target (Windows Job Objects) |
| REQ-027 | Global emergency stop; reports processes that could not be stopped; survives restart | 2 | Done (POSIX) · Untested on target (Windows) |
| REQ-028 | Per-job cancellation | 2 | Done |
| REQ-029 | Complete, tamper-evident audit log of actions and approvals | 2 | Partial: tamper-evident against row edits; role separation + keyed chain open (KI-002) |
| REQ-030 | Secret redaction in logs/audit/events/output; no secrets in source/frontend/browser storage | 2 | Done |
| REQ-031 | OS credential storage | 2 | Partial: keyring store + CLI done; Windows Credential Manager untested on target |
| REQ-032 | Rate limiting; CSRF/origin protection | 2 | Done |
| REQ-033 | Dependency / supply-chain checks | 2 | Done (CI: pip-audit, pnpm audit, gitleaks) |
| REQ-034 | Backup and recovery procedures | 2 | Partial: documented; restore test open (KI-008) |
| REQ-040 | Live 3D interface reflecting real backend state; reduced motion; low-power mode; GPU cleanup | 3–4 | Partial: core + 6 wired states; audio-reactive/voice states open |
| REQ-041 | Voice input/output | 4 | Open |
| REQ-050 | ChatGPT and Claude through supported integrations; provider registry | 5, 7 | Open |
| REQ-051 | Claude Code and Codex as controlled specialists with job tracking and isolation | 6 | Open |
| REQ-052 | Local model runtime chosen after discovery | 7 | Open |
| REQ-060 | Persistent, inspectable memory with provenance, correction, deletion, export | 8 | Open |
| REQ-070 | Workflow integration (n8n optional) | 10 | Open |
| REQ-080 | iPhone companion over authenticated private networking; device pairing and revocation | 11 | Open |
| REQ-090 | Production validation and independent audit sign-off | 12 | Open |
| REQ-100 | OmniRoute must not be reintroduced; LiteLLM only with evaluated need | all | Done (not present) |
