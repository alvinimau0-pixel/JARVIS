import type { CatalogOut, EventOut } from "@jarvis/contracts";
import { createContext, useContext, useEffect, useMemo, useReducer, useState } from "react";
import { ApiClient } from "../api/client";
import { discoverSession, type Session } from "../api/session";
import { EventStream, wsUrl } from "../events/adapter";
import { factsReducer, initialFacts, type Facts } from "../state/visual";

export interface Jarvis {
  session: Session | null;
  sessionError: string | null;
  client: ApiClient | null;
  facts: Facts;
  catalog: CatalogOut | null;
  /** Increments on every delivered backend event; lists refetch when it changes. */
  revision: number;
  recentEvents: EventOut[];
}

export const JarvisContext = createContext<Jarvis | null>(null);

export function useJarvisContext(): Jarvis {
  const ctx = useContext(JarvisContext);
  if (!ctx) throw new Error("JarvisContext missing");
  return ctx;
}

export function useJarvis(): Jarvis {
  const [session, setSession] = useState<Session | null>(null);
  const [sessionError, setSessionError] = useState<string | null>(null);
  const [facts, dispatch] = useReducer(factsReducer, initialFacts);
  const [catalog, setCatalog] = useState<CatalogOut | null>(null);
  const [revision, setRevision] = useState(0);
  const [recentEvents, setRecentEvents] = useState<EventOut[]>([]);

  useEffect(() => {
    discoverSession()
      .then((s) => (s ? setSession(s) : setSessionError("no-session")))
      .catch((e: unknown) => setSessionError(String(e)));
  }, []);

  const client = useMemo(() => (session ? new ApiClient(session) : null), [session]);

  useEffect(() => {
    if (!session || !client) return;
    const stream = new EventStream({
      url: wsUrl(session.baseUrl),
      token: session.token,
      fetchSince: (seq) => client.events(seq),
    });

    // Re-hydrate from authoritative snapshots every time the stream (re)opens.
    const hydrate = async () => {
      try {
        const [state, pending, tasks, cat] = await Promise.all([
          client.systemState(),
          client.approvals("pending"),
          client.tasks(100),
          client.catalog(),
        ]);
        const active = tasks.flatMap((t) => t.jobs).filter((j) => j.status === "running").map((j) => j.id);
        dispatch({
          type: "hydrate",
          activeJobs: active,
          pendingApprovals: pending.map((a) => a.id),
          emergencyStop: state.emergency_stop,
        });
        setCatalog(cat);
        setRevision((r) => r + 1);
      } catch {
        // Surfaced through health/offline state; nothing is assumed.
      }
    };

    const offState = stream.onState((s) => {
      dispatch({ type: "connection", state: s });
      if (s === "open") void hydrate();
    });
    const offEvent = stream.onEvent((event) => {
      dispatch({ type: "event", event, now: Date.now() });
      setRecentEvents((xs) => [event, ...xs].slice(0, 50));
      setRevision((r) => r + 1);
    });
    stream.start();
    return () => {
      offState();
      offEvent();
      stream.stop();
    };
  }, [session, client]);

  return { session, sessionError, client, facts, catalog, revision, recentEvents };
}

/** Re-render at most every `ms` so time-based transient states (e.g. COMPLETED) expire. */
export function useNow(ms = 1000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(t);
  }, [ms]);
  return now;
}

export function useMediaQuery(query: string): boolean {
  const get = () => typeof window !== "undefined" && typeof window.matchMedia === "function" && window.matchMedia(query).matches;
  const [match, setMatch] = useState(get);
  useEffect(() => {
    if (typeof window.matchMedia !== "function") return;
    const mq = window.matchMedia(query);
    const fn = () => setMatch(mq.matches);
    mq.addEventListener("change", fn);
    return () => mq.removeEventListener("change", fn);
  }, [query]);
  return match;
}
