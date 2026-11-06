import { useCallback, useState } from "react";
import { ApprovalsPanel } from "../panels/ApprovalsPanel";
import { AuditPanel } from "../panels/AuditPanel";
import { Drawer } from "../panels/Drawer";
import { EmergencyStop } from "../panels/EmergencyStop";
import { HealthPanel } from "../panels/HealthPanel";
import { Core } from "../scene/Core";
import { lookFor } from "../scene/palette";
import { BrainSection, ClaudeSection, CodexSection } from "../sections/Sections";
import { deriveVisual } from "../state/visual";
import { SECTIONS, type SectionId } from "./sections";
import { JarvisContext, useJarvis, useMediaQuery, useNow, type Jarvis } from "./useJarvis";

type DrawerId = "approvals" | "audit" | "health" | null;

export function App() {
  const jarvis = useJarvis();
  return (
    <JarvisContext.Provider value={jarvis}>
      <Shell jarvis={jarvis} />
    </JarvisContext.Provider>
  );
}

export function Shell({ jarvis }: { jarvis: Jarvis }) {
  const [section, setSection] = useState<SectionId>("brain");
  const [drawer, setDrawer] = useState<DrawerId>(null);
  const prefersReduced = useMediaQuery("(prefers-reduced-motion: reduce)");
  const [lowPower, setLowPower] = useState(false);
  const now = useNow(1000);
  const visual = deriveVisual(jarvis.facts, now);
  const look = lookFor(visual.state);
  const close = useCallback(() => setDrawer(null), []);
  const openApprovals = useCallback(() => setDrawer("approvals"), []);

  if (jarvis.sessionError) {
    return (
      <div className="boot">
        <h1 className="wordmark">JARVIS</h1>
        <p>No backend session.</p>
        <p className="muted small">
          Launch JARVIS from the desktop app. For development, run <code>scripts/dev.sh</code>, which starts the backend and gives this window a temporary session token.
        </p>
      </div>
    );
  }

  return (
    <div className="shell" style={{ ["--accent" as string]: look.css }} data-visual={visual.state}>
      <header className="topbar">
        <h1 className="wordmark">JARVIS</h1>
        <div className="state" role="status" aria-live="polite">
          <span className="state-dot" />
          <span className="state-name" data-testid="visual-state">{visual.state.replace("_", " ")}</span>
          <span className="state-label">{visual.label}</span>
        </div>
        <div className="top-actions">
          <button className="chip" onClick={() => setDrawer("approvals")} aria-label={`Approvals (${jarvis.facts.pendingApprovals.length} pending)`}>
            Approvals{jarvis.facts.pendingApprovals.length > 0 && <span className="badge">{jarvis.facts.pendingApprovals.length}</span>}
          </button>
          <button className="chip" onClick={() => setDrawer("audit")}>Audit</button>
          <button className="chip" onClick={() => setDrawer("health")}>Health</button>
          <button className="chip" aria-pressed={lowPower} onClick={() => setLowPower((v) => !v)} title="Lower frame rate and resolution of the 3D core">
            {lowPower ? "Low power: on" : "Low power: off"}
          </button>
          <EmergencyStop />
        </div>
      </header>

      <nav className="sections" aria-label="Primary">
        {SECTIONS.map((s) => (
          <button
            key={s.id}
            className="section-tab"
            aria-current={section === s.id ? "page" : undefined}
            onClick={() => setSection(s.id)}
            data-section={s.id}
          >
            <span className="section-label">{s.label}</span>
            <span className="section-hint">{s.hint}</span>
          </button>
        ))}
      </nav>

      <div className="stage">
        <Core state={visual.state} reducedMotion={prefersReduced} lowPower={lowPower} />
      </div>

      <main className="content" aria-label={SECTIONS.find((s) => s.id === section)?.label}>
        {section === "claude" && <ClaudeSection />}
        {section === "codex" && <CodexSection onApprovalRequired={openApprovals} />}
        {section === "brain" && <BrainSection onOpen={setDrawer} />}
      </main>

      <Drawer title="Approvals" open={drawer === "approvals"} onClose={close}>
        <ApprovalsPanel />
      </Drawer>
      <Drawer title="Audit log" open={drawer === "audit"} onClose={close}>
        <AuditPanel />
      </Drawer>
      <Drawer title="System health" open={drawer === "health"} onClose={close}>
        <HealthPanel onOpenApprovals={openApprovals} />
      </Drawer>
    </div>
  );
}
