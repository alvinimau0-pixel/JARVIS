import type { ActionResponse } from "@jarvis/contracts";
import { useState, type FormEvent } from "react";
import { useJarvisContext } from "../app/useJarvis";
import { splitArgs } from "./argv";
import { Empty, ErrorLine, LevelBadge } from "./common";

/**
 * Submits `exec.run` actions. The backend validates the executable against its allowlist,
 * checks arguments, enforces workspace containment and decides the permission level.
 */
export function ExecConsole({ onApprovalRequired }: { onApprovalRequired: () => void }) {
  const { client, catalog } = useJarvisContext();
  const [workspace, setWorkspace] = useState("");
  const [executable, setExecutable] = useState("");
  const [args, setArgs] = useState("status --porcelain");
  const [cwd, setCwd] = useState(".");
  const [result, setResult] = useState<ActionResponse | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  if (!client || !catalog) return <p className="muted">Waiting for backend…</p>;
  if (catalog.workspaces.length === 0)
    return (
      <Empty title="No approved workspaces">
        Set <code>JARVIS_WORKSPACES</code> to one or more project folders. Execution outside approved workspaces is denied.
      </Empty>
    );

  const ws = workspace || catalog.workspaces[0] || "";
  const exe = executable || catalog.executables[0]?.name || "";
  const level = catalog.executables.find((e) => e.name === exe)?.level;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const argv = splitArgs(args);
      const r = await client.submit({ action: "exec.run", params: { executable: exe, args: argv, workspace: ws, cwd }, reason: "Operator console" });
      setResult(r);
      if (r.status === "approval_required") onApprovalRequired();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="console" onSubmit={submit} aria-label="Controlled execution">
      <div className="console-row">
        <label>
          Workspace
          <select value={ws} onChange={(e) => setWorkspace(e.target.value)}>
            {catalog.workspaces.map((w) => <option key={w}>{w}</option>)}
          </select>
        </label>
        <label>
          Executable
          <select value={exe} onChange={(e) => setExecutable(e.target.value)}>
            {catalog.executables.map((x) => (
              <option key={x.name} value={x.name}>{x.name} (L{x.level})</option>
            ))}
          </select>
        </label>
        <label className="grow">
          Arguments
          <input value={args} onChange={(e) => setArgs(e.target.value)} spellCheck={false} aria-label="Arguments" />
        </label>
        <label>
          Directory
          <input value={cwd} onChange={(e) => setCwd(e.target.value)} spellCheck={false} className="narrow" />
        </label>
        <button className="btn btn-primary" disabled={busy} type="submit">
          Submit
        </button>
      </div>
      <p className="muted small">
        <LevelBadge level={level} /> No shell is involved. The backend checks every argument and runs it inside the workspace with a scrubbed environment and a timeout.
      </p>
      <ErrorLine error={error} />
      {result?.status === "accepted" && (
        <p className="notice" role="status">Accepted as L{result.level} · job {result.job_id?.slice(0, 8)}. Live status appears below.</p>
      )}
      {result?.status === "approval_required" && (
        <p className="notice warn" role="status">L{result.level} action. It needs your approval before it can run.</p>
      )}
    </form>
  );
}
