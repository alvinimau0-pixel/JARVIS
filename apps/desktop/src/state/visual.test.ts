import type { EventOut } from "@jarvis/contracts";
import { describe, expect, it } from "vitest";
import { deriveVisual, factsReducer, initialFacts, OUTCOME_DISPLAY_MS, type Facts } from "./visual";

let seq = 0;
const ev = (type: EventOut["type"], extra: Partial<EventOut> = {}): EventOut => ({
  id: crypto.randomUUID(),
  seq: ++seq,
  type,
  source: "test",
  task_id: null,
  job_id: null,
  ts: new Date().toISOString(),
  payload: {},
  ...extra,
});

const open: Facts = { ...initialFacts, connection: "open" };
const apply = (f: Facts, e: EventOut, now = 1000) => factsReducer(f, { type: "event", event: e, now });

describe("visual state", () => {
  it("is OFFLINE unless the event stream is open", () => {
    expect(deriveVisual(initialFacts, 0).state).toBe("OFFLINE");
    expect(deriveVisual({ ...initialFacts, connection: "connecting" }, 0).label).toBe("Connecting…");
  });

  it("is IDLE when connected with nothing happening (no invented activity)", () => {
    expect(deriveVisual(open, 0)).toEqual({ state: "IDLE", label: "Idle" });
  });

  it("follows a job from start to completion, then decays back to IDLE", () => {
    let f = apply(open, ev("job.started", { job_id: "j1" }));
    expect(deriveVisual(f, 1000).state).toBe("EXECUTING");
    f = apply(f, ev("job.completed", { job_id: "j1" }), 2000);
    expect(deriveVisual(f, 2000).state).toBe("COMPLETED");
    expect(deriveVisual(f, 2000 + OUTCOME_DISPLAY_MS + 1).state).toBe("IDLE");
  });

  it("shows ERROR for failed jobs", () => {
    let f = apply(open, ev("job.started", { job_id: "j1" }));
    f = apply(f, ev("job.failed", { job_id: "j1", payload: { status: "timed_out" } }), 5000);
    expect(deriveVisual(f, 5000)).toEqual({ state: "ERROR", label: "Job timed_out" });
  });

  it("waits for approval until granted or denied", () => {
    let f = apply(open, ev("approval.required", { payload: { approval_id: "a1" } }));
    expect(deriveVisual(f, 0).state).toBe("WAITING_APPROVAL");
    f = apply(f, ev("approval.required", { payload: { approval_id: "a1" } })); // duplicate
    expect(f.pendingApprovals).toEqual(["a1"]);
    f = apply(f, ev("approval.denied", { payload: { approval_id: "a1" } }));
    expect(deriveVisual(f, 0).state).toBe("IDLE");
  });

  it("emergency stop is sticky until reset and clears active jobs", () => {
    let f = apply(open, ev("job.started", { job_id: "j1" }));
    f = apply(f, ev("system.emergency_stop"));
    expect(deriveVisual(f, 0)).toEqual({ state: "ERROR", label: "Emergency stop active" });
    expect(f.activeJobs).toEqual([]);
    f = apply(f, ev("system.emergency_reset"));
    expect(deriveVisual(f, 0).state).toBe("IDLE");
  });

  it("hydrates from backend snapshots", () => {
    const f = factsReducer(open, { type: "hydrate", activeJobs: ["x"], pendingApprovals: [], emergencyStop: false });
    expect(deriveVisual(f, 0).state).toBe("EXECUTING");
  });
});
