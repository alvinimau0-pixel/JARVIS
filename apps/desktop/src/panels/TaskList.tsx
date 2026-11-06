import type { TaskOut } from "@jarvis/contracts";
import { useEffect, useState } from "react";
import { useJarvisContext } from "../app/useJarvis";
import { Empty, ErrorLine, fmtTime, StatusPill } from "./common";

interface Props {
  owner?: string;
  emptyTitle: string;
  emptyBody?: string;
  limit?: number;
}

export function TaskList({ owner, emptyTitle, emptyBody, limit = 20 }: Props) {
  const { client, revision } = useJarvisContext();
  const [tasks, setTasks] = useState<TaskOut[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [open, setOpen] = useState<string | null>(null);

  useEffect(() => {
    client?.tasks(100).then(setTasks).catch(setError);
  }, [client, revision]);

  if (!client) return null;
  const shown = (tasks ?? []).filter((t) => !owner || t.jobs.some((j) => j.owner === owner)).slice(0, limit);

  return (
    <div className="tasks">
      <ErrorLine error={error} />
      {tasks === null && !error && <p className="muted">Loading…</p>}
      {tasks !== null && shown.length === 0 && <Empty title={emptyTitle}>{emptyBody}</Empty>}
      <ul>
        {shown.map((t) => (
          <li key={t.id} className="task" data-testid="task" data-status={t.status}>
            <button className="task-head" onClick={() => setOpen(open === t.id ? null : t.id)} aria-expanded={open === t.id}>
              <StatusPill status={t.status} />
              <span className="task-title">{t.title}</span>
              <span className="muted small">{fmtTime(t.created_at)}</span>
            </button>
            {open === t.id &&
              t.jobs.map((j) => (
                <div key={j.id} className="job">
                  <p className="small muted">
                    job {j.id.slice(0, 8)} · {j.status} · exit {j.exit_code ?? "—"} · pid {j.pid ?? "—"}
                    {j.output_truncated && " · output truncated"}
                  </p>
                  {j.status === "running" && (
                    <button className="btn btn-ghost small" onClick={() => client.cancelJob(j.id).catch(setError)}>
                      Cancel job
                    </button>
                  )}
                  {j.error && <p className="bad small">{j.error}</p>}
                  {j.stdout && <pre className="out">{j.stdout}</pre>}
                  {j.stderr && <pre className="out err">{j.stderr}</pre>}
                </div>
              ))}
          </li>
        ))}
      </ul>
    </div>
  );
}
