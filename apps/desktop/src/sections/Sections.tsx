import { useJarvisContext } from "../app/useJarvis";
import { ExecConsole } from "../panels/ExecConsole";
import { TaskList } from "../panels/TaskList";

function Integration({ name, status, phase }: { name: string; status: string; phase: string }) {
  return (
    <div className="integration" data-status="not-configured">
      <span className="integration-name">{name}</span>
      <span className="integration-status">{status}</span>
      <span className="muted small">{phase}</span>
    </div>
  );
}

export function ClaudeSection() {
  return (
    <div className="section-body">
      <p className="lede">Claude intelligence, Claude Code, research and architecture work.</p>
      <div className="integrations">
        <Integration name="Claude" status="Not configured" phase="Provider adapter: Phase 5" />
        <Integration name="Claude Code" status="Not integrated" phase="Specialist execution: Phase 6" />
      </div>
      <h3>Job history</h3>
      <TaskList owner="claude_code" emptyTitle="No Claude Code jobs" emptyBody="The Claude Code integration isn't built yet, so there's no history to show." />
    </div>
  );
}

export function CodexSection({ onApprovalRequired }: { onApprovalRequired: () => void }) {
  return (
    <div className="section-body">
      <p className="lede">Engineering, terminal, testing and Git.</p>
      <div className="integrations">
        <Integration name="Codex" status="Not integrated" phase="Specialist execution: Phase 6" />
      </div>
      <h3>Controlled terminal</h3>
      <ExecConsole onApprovalRequired={onApprovalRequired} />
      <h3>Execution history</h3>
      <TaskList owner="exec" emptyTitle="Nothing has run yet" emptyBody="Commands submitted above appear here with their real output." />
    </div>
  );
}

export function BrainSection({ onOpen }: { onOpen: (d: "approvals" | "audit" | "health") => void }) {
  const { facts, catalog } = useJarvisContext();
  return (
    <div className="section-body">
      <p className="lede">The JARVIS commander: orchestration, providers, memory and security.</p>
      <div className="grid">
        <section className="card">
          <h3>Commander</h3>
          <p className="muted">No model provider is configured, so there's no conversation yet. ChatGPT and Claude adapters arrive in Phase 5.</p>
        </section>
        <section className="card">
          <h3>Security</h3>
          <p>
            Emergency stop: <strong className={facts.emergencyStop ? "bad" : "ok"}>{facts.emergencyStop ? "ACTIVE" : "clear"}</strong>
          </p>
          <p>Pending approvals: <strong>{facts.pendingApprovals.length}</strong></p>
          <div className="row">
            <button className="btn btn-ghost" onClick={() => onOpen("approvals")}>Approvals</button>
            <button className="btn btn-ghost" onClick={() => onOpen("audit")}>Audit log</button>
            <button className="btn btn-ghost" onClick={() => onOpen("health")}>System health</button>
          </div>
        </section>
        <section className="card">
          <h3>Providers and models</h3>
          <p className="muted">No providers registered yet. The local model runtime will be chosen after you run the hardware discovery report on your PC.</p>
        </section>
        <section className="card">
          <h3>Memory</h3>
          <p className="muted">Persistent memory isn't implemented yet (Phase 8).</p>
        </section>
        <section className="card">
          <h3>Capabilities</h3>
          <ul className="caps">
            {catalog?.actions.map((a) => (
              <li key={a.name}><code>{a.name}</code> <span className="muted small">{a.description}</span></li>
            ))}
          </ul>
        </section>
      </div>
      <h3>All tasks</h3>
      <TaskList emptyTitle="No tasks yet" />
    </div>
  );
}
