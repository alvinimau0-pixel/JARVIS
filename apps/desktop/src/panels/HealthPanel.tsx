import type { HealthOut } from "@jarvis/contracts";
import { useEffect, useState } from "react";
import { useJarvisContext } from "../app/useJarvis";
import { ErrorLine } from "./common";

export function HealthPanel({ onOpenApprovals }: { onOpenApprovals: () => void }) {
  const { client, revision, facts, session } = useJarvisContext();
  const [health, setHealth] = useState<HealthOut | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    client?.health().then(setHealth).catch(setError);
  }, [client, revision]);

  if (!client) return null;
  const requestReset = async () => {
    setError(null);
    try {
      const r = await client.submit({ action: "system.emergency_reset", params: {}, reason: "Operator requested reset" });
      if (r.status === "approval_required") {
        setNotice("Reset is L3 CRITICAL: approve it in Approvals, then run it.");
        onOpenApprovals();
      }
    } catch (e) {
      setError(e);
    }
  };

  return (
    <div className="stack">
      <ErrorLine error={error} />
      {notice && <p className="notice" role="status">{notice}</p>}
      {health && (
        <>
          <p>
            Backend <strong className={health.status === "ok" ? "ok" : "bad"}>{health.status}</strong> · v{health.version} · API {health.api_version} · session via {session?.source}
          </p>
          <ul className="checks">
            {health.checks.map((c) => (
              <li key={c.name} className={c.ok ? "ok" : "bad"}>
                <span className="dot" /> <strong>{c.name}</strong> <span className="muted">{c.detail}</span>
              </li>
            ))}
          </ul>
        </>
      )}
      {facts.emergencyStop && (
        <button className="btn btn-primary" onClick={requestReset}>
          Request emergency-stop reset (L3)
        </button>
      )}
    </div>
  );
}
