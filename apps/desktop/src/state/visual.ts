/**
 * Visual state machine. The rendered state is DERIVED from backend facts (events + hydrated
 * snapshots) and the connection state. Nothing here invents progress or activity.
 */
import type { EventOut } from "@jarvis/contracts";
import type { ConnectionState } from "../events/adapter";

export type VisualState =
  | "IDLE"
  | "LISTENING" // voice input (Phase 4) - not yet wired
  | "THINKING" // model call in flight (Phase 5) - not yet wired
  | "SPEAKING" // TTS output (Phase 4) - not yet wired
  | "RESEARCHING" // (Phase 5+) - not yet wired
  | "PLANNING" // (Phase 6+) - not yet wired
  | "DELEGATING" // (Phase 6+) - not yet wired
  | "CLAUDE_WORKING" // (Phase 6) - not yet wired
  | "CODEX_WORKING" // (Phase 6) - not yet wired
  | "EXECUTING" // controlled job running (job.started .. job.completed/failed/cancelled)
  | "DEBUGGING" // (Phase 6+) - not yet wired
  | "AUDITING" // (Phase 12) - not yet wired
  | "WAITING_APPROVAL" // approval.required with no decision yet
  | "COMPLETED" // transient local state after a job completes successfully
  | "ERROR" // job failure (transient) or emergency stop latched (sticky)
  | "OFFLINE"; // event stream not connected

export const WIRED_STATES: readonly VisualState[] = [
  "IDLE",
  "EXECUTING",
  "WAITING_APPROVAL",
  "COMPLETED",
  "ERROR",
  "OFFLINE",
];

export interface Facts {
  connection: ConnectionState;
  activeJobs: string[];
  pendingApprovals: string[];
  emergencyStop: boolean;
  lastOutcome: { kind: "completed" | "failed"; at: number; label: string } | null;
  lastEvent: EventOut | null;
}

export const initialFacts: Facts = {
  connection: "closed",
  activeJobs: [],
  pendingApprovals: [],
  emergencyStop: false,
  lastOutcome: null,
  lastEvent: null,
};

export type FactsAction =
  | { type: "connection"; state: ConnectionState }
  | {
      type: "hydrate";
      activeJobs: string[];
      pendingApprovals: string[];
      emergencyStop: boolean;
    }
  | { type: "event"; event: EventOut; now: number };

const without = (xs: string[], x: string) => xs.filter((y) => y !== x);
const withItem = (xs: string[], x: string) => (xs.includes(x) ? xs : [...xs, x]);

export function factsReducer(f: Facts, a: FactsAction): Facts {
  switch (a.type) {
    case "connection":
      return { ...f, connection: a.state };
    case "hydrate":
      return {
        ...f,
        activeJobs: a.activeJobs,
        pendingApprovals: a.pendingApprovals,
        emergencyStop: a.emergencyStop,
      };
    case "event": {
      const e = a.event;
      const p = e.payload as Record<string, unknown>;
      const next: Facts = { ...f, lastEvent: e };
      switch (e.type) {
        case "job.started":
          if (e.job_id) next.activeJobs = withItem(f.activeJobs, e.job_id);
          return next;
        case "job.completed":
          if (e.job_id) next.activeJobs = without(f.activeJobs, e.job_id);
          next.lastOutcome = { kind: "completed", at: a.now, label: "Job completed" };
          return next;
        case "job.failed":
        case "job.cancelled":
          if (e.job_id) next.activeJobs = without(f.activeJobs, e.job_id);
          next.lastOutcome = {
            kind: "failed",
            at: a.now,
            label: e.type === "job.cancelled" ? "Job cancelled" : `Job ${String(p.status ?? "failed")}`,
          };
          return next;
        case "approval.required":
          if (typeof p.approval_id === "string")
            next.pendingApprovals = withItem(f.pendingApprovals, p.approval_id);
          return next;
        case "approval.granted":
        case "approval.denied":
          if (typeof p.approval_id === "string")
            next.pendingApprovals = without(f.pendingApprovals, p.approval_id);
          return next;
        case "system.emergency_stop":
          return { ...next, emergencyStop: true, activeJobs: [] };
        case "system.emergency_reset":
          return { ...next, emergencyStop: false };
        case "system.recovered":
          return { ...next, emergencyStop: Boolean(p.emergency_stop) };
        default:
          return next;
      }
    }
  }
}

export const OUTCOME_DISPLAY_MS = 4000;

export interface Derived {
  state: VisualState;
  label: string;
}

export function deriveVisual(f: Facts, now: number): Derived {
  if (f.connection !== "open")
    return { state: "OFFLINE", label: f.connection === "connecting" ? "Connecting…" : "Offline" };
  if (f.emergencyStop) return { state: "ERROR", label: "Emergency stop active" };
  if (f.pendingApprovals.length > 0)
    return {
      state: "WAITING_APPROVAL",
      label: `${f.pendingApprovals.length} approval${f.pendingApprovals.length > 1 ? "s" : ""} waiting`,
    };
  if (f.activeJobs.length > 0)
    return {
      state: "EXECUTING",
      label: `${f.activeJobs.length} job${f.activeJobs.length > 1 ? "s" : ""} running`,
    };
  if (f.lastOutcome && now - f.lastOutcome.at < OUTCOME_DISPLAY_MS)
    return {
      state: f.lastOutcome.kind === "completed" ? "COMPLETED" : "ERROR",
      label: f.lastOutcome.label,
    };
  return { state: "IDLE", label: "Idle" };
}
