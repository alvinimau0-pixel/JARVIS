import type { EmergencyStopReport } from "@jarvis/contracts";
import { useState } from "react";
import { useJarvisContext } from "../app/useJarvis";

/** Always visible. One press, no confirmation: stopping is always safe. */
export function EmergencyStop() {
  const { client, facts } = useJarvisContext();
  const [report, setReport] = useState<EmergencyStopReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const stop = async () => {
    if (!client) return;
    setBusy(true);
    setError(null);
    try {
      setReport(await client.emergencyStop());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="estop-wrap">
      <button
        className={`estop ${facts.emergencyStop ? "estop-latched" : ""}`}
        onClick={stop}
        disabled={!client || busy}
        aria-label="Emergency stop: cancel all jobs and block new execution"
      >
        {facts.emergencyStop ? "STOPPED" : busy ? "STOPPING…" : "STOP"}
      </button>
      {report && (
        <span className="estop-report" role="status">
          {report.jobs_cancelled} job(s) cancelled ·{" "}
          {report.unstopped.length === 0 ? "all processes stopped" : `${report.unstopped.length} process(es) NOT confirmed stopped`}
          {!report.persisted && " · WARNING: not saved (database unavailable); stop lasts until backend restart"}
        </span>
      )}
      {error && <span className="bad small" role="alert">{error}</span>}
    </div>
  );
}
