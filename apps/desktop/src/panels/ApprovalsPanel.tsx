import type { ApprovalOut } from "@jarvis/contracts";
import { useEffect, useState } from "react";
import { useJarvisContext } from "../app/useJarvis";
import { Empty, ErrorLine, fmtTime, LevelBadge, StatusPill } from "./common";

/**
 * Shows the EXACT action and parameters being approved. Approve/Reject are enforced by the
 * backend; this view only reports the confirmed result.
 */
export function ApprovalsPanel() {
  const { client, revision } = useJarvisContext();
  const [items, setItems] = useState<ApprovalOut[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    if (!client) return;
    client
      .approvals()
      .then((xs) => setItems(xs.filter((a) => a.status === "pending" || a.status === "approved").slice(0, 30)))
      .catch(setError);
  }, [client, revision]);

  if (!client) return null;

  const act = async (fn: () => Promise<unknown>, id: string, done: string) => {
    setBusy(id);
    setError(null);
    setNotice(null);
    try {
      await fn();
      setNotice(done);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="stack">
      <ErrorLine error={error} />
      {notice && <p className="notice" role="status">{notice}</p>}
      {items === null && <p className="muted">Loading…</p>}
      {items?.length === 0 && <Empty title="Nothing waiting for approval">L2 and L3 actions appear here with their exact parameters.</Empty>}
      {items?.map((a) => (
        <article key={a.id} className="approval" data-testid="approval">
          <header>
            <LevelBadge level={a.level} />
            <StatusPill status={a.status} />
            <span className="muted small">expires {fmtTime(a.expires_at)}</span>
          </header>
          <p className="approval-target">{a.target}</p>
          <dl className="kv">
            <dt>Action</dt>
            <dd><code>{a.action}</code></dd>
            <dt>Requested by</dt>
            <dd>{a.requester_kind}:{a.requester_id}</dd>
            <dt>Reason</dt>
            <dd>{a.reason}</dd>
            <dt>Params hash</dt>
            <dd><code className="small">{a.params_hash.slice(0, 16)}…</code></dd>
          </dl>
          <pre className="params">{JSON.stringify(a.params, null, 2)}</pre>
          <footer className="row">
            {a.status === "pending" && (
              <>
                <button className="btn btn-approve" disabled={busy === a.id} onClick={() => act(() => client.approve(a.id), a.id, "Approved. Run it below when ready.")}>
                  Approve
                </button>
                <button className="btn btn-ghost" disabled={busy === a.id} onClick={() => act(() => client.deny(a.id), a.id, "Rejected.")}>
                  Reject
                </button>
              </>
            )}
            {a.status === "approved" && a.requester_kind === "human" && (
              <button
                className="btn btn-primary"
                disabled={busy === a.id}
                onClick={() =>
                  act(
                    () => client.submit({ action: a.action, params: a.params, reason: a.reason, approval_id: a.id }),
                    a.id,
                    "Submitted with approval. Watch the task list for the result.",
                  )
                }
              >
                Run approved action
              </button>
            )}
          </footer>
        </article>
      ))}
    </div>
  );
}
