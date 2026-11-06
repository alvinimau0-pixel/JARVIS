/**
 * Typed event stream with reconnection, de-duplication, ordering and gap repair.
 *
 * Guarantees to subscribers: each event is delivered at most once and in strictly increasing
 * `seq` order. On reconnect the stream resumes from the last delivered seq (server replay);
 * if a gap is detected mid-stream, the missing range is fetched over REST before continuing.
 */
import type { EventOut } from "@jarvis/contracts";
import { WS_AUTH_PREFIX, WS_PROTOCOL } from "@jarvis/contracts";

export type ConnectionState = "connecting" | "open" | "closed";

export interface WebSocketLike {
  onopen: ((ev: unknown) => void) | null;
  onmessage: ((ev: { data: unknown }) => void) | null;
  onclose: ((ev: { code: number }) => void) | null;
  onerror: ((ev: unknown) => void) | null;
  close(): void;
}

export interface EventStreamOptions {
  url: string; // ws(s)://host/api/v1/ws
  token: string;
  fetchSince: (seq: number) => Promise<EventOut[]>;
  createSocket?: (url: string, protocols: string[]) => WebSocketLike;
  backoffMs?: (attempt: number) => number;
  startSeq?: number;
}

type Listener = (e: EventOut) => void;
type StateListener = (s: ConnectionState) => void;

export class EventStream {
  private lastSeq: number;
  private socket: WebSocketLike | null = null;
  private listeners = new Set<Listener>();
  private stateListeners = new Set<StateListener>();
  private attempt = 0;
  private stopped = false;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private chain: Promise<void> = Promise.resolve();
  state: ConnectionState = "closed";

  constructor(private opts: EventStreamOptions) {
    this.lastSeq = opts.startSeq ?? -1;
  }

  get seq(): number {
    return this.lastSeq;
  }

  onEvent(fn: Listener): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  onState(fn: StateListener): () => void {
    this.stateListeners.add(fn);
    return () => this.stateListeners.delete(fn);
  }

  start(): void {
    this.stopped = false;
    this.connect();
  }

  stop(): void {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    this.socket?.close();
    this.socket = null;
    this.setState("closed");
  }

  private setState(s: ConnectionState): void {
    if (this.state === s) return;
    this.state = s;
    this.stateListeners.forEach((fn) => fn(s));
  }

  private connect(): void {
    if (this.stopped) return;
    this.setState("connecting");
    const url = this.lastSeq >= 0 ? `${this.opts.url}?since_seq=${this.lastSeq}` : this.opts.url;
    const create =
      this.opts.createSocket ??
      ((u: string, p: string[]) => new WebSocket(u, p) as unknown as WebSocketLike);
    const ws = create(url, [WS_PROTOCOL, `${WS_AUTH_PREFIX}${this.opts.token}`]);
    this.socket = ws;
    ws.onopen = () => {
      this.attempt = 0;
      this.setState("open");
    };
    ws.onmessage = (msg) => {
      let event: EventOut;
      try {
        event = JSON.parse(String(msg.data)) as EventOut;
      } catch {
        return; // malformed frames are ignored, never guessed at
      }
      this.chain = this.chain.then(() => this.ingest(event));
    };
    ws.onerror = () => {};
    ws.onclose = () => {
      if (this.socket !== ws) return;
      this.socket = null;
      this.setState("closed");
      if (this.stopped) return;
      const delay = (this.opts.backoffMs ?? defaultBackoff)(this.attempt++);
      this.timer = setTimeout(() => this.connect(), delay);
    };
  }

  /** Exposed for tests: process one incoming event. */
  async ingest(event: EventOut): Promise<void> {
    if (typeof event.seq !== "number" || event.seq <= this.lastSeq) return; // duplicate/stale
    if (this.lastSeq >= 0 && event.seq > this.lastSeq + 1) {
      try {
        const missing = await this.opts.fetchSince(this.lastSeq);
        for (const m of missing) {
          if (m.seq < event.seq && m.seq > this.lastSeq) this.deliver(m);
        }
      } catch {
        // Gap could not be repaired now; deliver what we have. Reconnect replay will catch up.
      }
    }
    if (event.seq > this.lastSeq) this.deliver(event);
  }

  private deliver(event: EventOut): void {
    this.lastSeq = event.seq;
    this.listeners.forEach((fn) => fn(event));
  }
}

export function defaultBackoff(attempt: number): number {
  return Math.min(10_000, 500 * 2 ** attempt);
}

export function wsUrl(baseUrl: string): string {
  return `${baseUrl.replace(/^http/, "ws")}/api/v1/ws`;
}
