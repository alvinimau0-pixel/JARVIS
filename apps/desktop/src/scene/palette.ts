import type { VisualState } from "../state/visual";

export interface StateLook {
  color: number;
  css: string;
  spin: number; // radians/sec at full motion
  pulse: number; // Hz, 0 = steady
  intensity: number;
}

const CYAN = { color: 0x5fd4ff, css: "#5fd4ff" };
const AMBER = { color: 0xffb547, css: "#ffb547" };
const RED = { color: 0xff4d5e, css: "#ff4d5e" };
const GREEN = { color: 0x5cf2a6, css: "#5cf2a6" };
const GREY = { color: 0x5a6672, css: "#5a6672" };

export function lookFor(state: VisualState): StateLook {
  switch (state) {
    case "EXECUTING":
    case "CODEX_WORKING":
    case "CLAUDE_WORKING":
    case "DEBUGGING":
      return { ...AMBER, spin: 1.1, pulse: 0, intensity: 1 };
    case "WAITING_APPROVAL":
      return { ...AMBER, spin: 0.15, pulse: 0.8, intensity: 0.9 };
    case "COMPLETED":
      return { ...GREEN, spin: 0.3, pulse: 0, intensity: 0.9 };
    case "ERROR":
      return { ...RED, spin: 0.05, pulse: 0.5, intensity: 1 };
    case "OFFLINE":
      return { ...GREY, spin: 0, pulse: 0, intensity: 0.35 };
    case "THINKING":
    case "PLANNING":
    case "RESEARCHING":
    case "DELEGATING":
      return { ...CYAN, spin: 0.7, pulse: 1.2, intensity: 1 };
    default:
      return { ...CYAN, spin: 0.12, pulse: 0.18, intensity: 0.7 };
  }
}
