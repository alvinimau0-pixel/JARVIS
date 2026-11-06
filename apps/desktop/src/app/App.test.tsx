import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { initialFacts } from "../state/visual";
import { Shell } from "./App";
import { SECTIONS } from "./sections";
import { JarvisContext, type Jarvis } from "./useJarvis";

const offline: Jarvis = {
  session: null,
  sessionError: null,
  client: null,
  facts: initialFacts,
  catalog: null,
  revision: 0,
  recentEvents: [],
};

function renderShell(j: Jarvis = offline) {
  return render(
    <JarvisContext.Provider value={j}>
      <Shell jarvis={j} />
    </JarvisContext.Provider>,
  );
}

describe("primary navigation", () => {
  it("defines exactly three primary sections", () => {
    expect(SECTIONS.map((s) => s.label)).toEqual(["CLAUDE", "CODEX", "BRAIN & WORKFLOW"]);
  });

  it("renders exactly three primary navigation entries", () => {
    renderShell();
    const nav = screen.getByRole("navigation", { name: "Primary" });
    expect(within(nav).getAllByRole("button")).toHaveLength(3);
  });

  it("shows OFFLINE when there is no live event stream", () => {
    renderShell();
    expect(screen.getByTestId("visual-state")).toHaveTextContent("OFFLINE");
  });

  it("keeps the emergency stop visible", () => {
    renderShell();
    expect(screen.getByRole("button", { name: /emergency stop/i })).toBeInTheDocument();
  });

  it("explains how to start when no backend session exists", () => {
    renderShell({ ...offline, sessionError: "no-session" });
    expect(screen.getByText("No backend session.")).toBeInTheDocument();
  });
});
