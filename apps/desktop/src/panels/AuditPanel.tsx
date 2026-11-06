import type { AuditEntryOut, AuditVerifyOut } from "@jarvis/contracts";
import { useEffect, useState } from "react";
import { useJarvisContext } from "../app/useJarvis";
import { ErrorLine, fmtTime, LevelBadge } from "./common";

export function AuditPanel() {
  const { client, revision } = useJarvisContext();
  const [rows, setRows] = useState<AuditEntryOut[]>([]);
  const [verify, setVerify] = useState<AuditVerifyOut | null>(null);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    client?.audit(60).then(setRows).catch(setError);
  }, [client, revision]);

  if (!client) return null;
  return (
    <div className="stack">
      <div className="row">
        <button className="btn btn-ghost" onClick={() => client.verifyAudit().then(setVerify).catch(setError)}>
          Verify hash chain
        </button>
        {verify && (
          <span className={verify.ok ? "ok" : "bad"} role="status">
            {verify.ok ? `Intact · ${verify.checked} entries` : `BROKEN at #${verify.first_bad_id}: ${verify.detail}`}
          </span>
        )}
      </div>
      <ErrorLine error={error} />
      <table className="audit">
        <thead>
          <tr><th>#</th><th>Time</th><th>Actor</th><th>Action</th><th>Level</th><th>Decision</th></tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id} title={r.target}>
              <td>{r.id}</td>
              <td>{fmtTime(r.ts)}</td>
              <td>{r.actor_kind}</td>
              <td><code>{r.action}</code></td>
              <td><LevelBadge level={r.level} /></td>
              <td className={`decision decision-${r.decision}`}>{r.decision}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
