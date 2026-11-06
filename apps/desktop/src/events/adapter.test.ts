import type { EventOut } from "@jarvis/contracts";
import { describe, expect, it, vi } from "vitest";
import { EventStream, type WebSocketLike } from "./adapter";

const ev = (seq: number, type: EventOut["type"] = "task.created"): EventOut => ({
  id: `00000000-0000-0000-0000-${String(seq).padStart(12, "0")}`,
  seq,
  type,
  source: "test",
  task_id: null,
  job_id: null,
  ts: new Date(0).toISOString(),
  payload: {},
});

class FakeSocket implements WebSocketLike {
  onopen: WebSocketLike["onopen"] = null;
  onmessage: WebSocketLike["onmessage"] = null;
  onclose: WebSocketLike["onclose"] = null;
  onerror: WebSocketLike["onerror"] = null;
  closed = false;
  constructor(
    public url: string,
    public protocols: string[],
  ) {}
  close() {
    this.closed = true;
  }
  send(e: EventOut) {
    this.onmessage?.({ data: JSON.stringify(e) });
  }
}

type FetchSince = (seq: number) => Promise<EventOut[]>;

function setup(fetchSince: FetchSince = vi.fn(async () => [] as EventOut[])) {
  const sockets: FakeSocket[] = [];
  const stream = new EventStream({
    url: "ws://127.0.0.1:1/api/v1/ws",
    token: "tok",
    fetchSince,
    createSocket: (u, p) => {
      const s = new FakeSocket(u, p);
      sockets.push(s);
      return s;
    },
    backoffMs: () => 0,
  });
  const got: number[] = [];
  stream.onEvent((e) => got.push(e.seq));
  return { stream, sockets, got, fetchSince };
}

const flush = () => new Promise((r) => setTimeout(r, 0));

describe("EventStream", () => {
  it("authenticates with the jarvis subprotocol and token", () => {
    const { stream, sockets } = setup();
    stream.start();
    expect(sockets[0]!.protocols).toEqual(["jarvis.v1", "auth.tok"]);
  });

  it("drops duplicate and stale events", async () => {
    const { stream, sockets, got } = setup();
    stream.start();
    const s = sockets[0]!;
    [1, 2, 2, 1, 3, 3].forEach((n) => s.send(ev(n)));
    await flush();
    expect(got).toEqual([1, 2, 3]);
  });

  it("repairs gaps from the REST replay before delivering newer events", async () => {
    const fetchSince = vi.fn(async (since: number) => [ev(since + 1), ev(since + 2), ev(since + 3)]);
    const { stream, sockets, got } = setup(fetchSince);
    stream.start();
    sockets[0]!.send(ev(1));
    sockets[0]!.send(ev(4)); // 2 and 3 were missed
    await flush();
    await flush();
    expect(fetchSince).toHaveBeenCalledWith(1);
    expect(got).toEqual([1, 2, 3, 4]);
  });

  it("ignores malformed frames", async () => {
    const { stream, sockets, got } = setup();
    stream.start();
    sockets[0]!.onmessage?.({ data: "{not json" });
    sockets[0]!.send(ev(1));
    await flush();
    expect(got).toEqual([1]);
  });

  it("reconnects resuming from the last delivered seq and reports state", async () => {
    const { stream, sockets } = setup();
    const states: string[] = [];
    stream.onState((s) => states.push(s));
    stream.start();
    sockets[0]!.onopen?.({});
    sockets[0]!.send(ev(7));
    await flush();
    sockets[0]!.onclose?.({ code: 1006 });
    await new Promise((r) => setTimeout(r, 5));
    expect(sockets).toHaveLength(2);
    expect(sockets[1]!.url).toBe("ws://127.0.0.1:1/api/v1/ws?since_seq=7");
    expect(states).toEqual(["connecting", "open", "closed", "connecting"]);
  });

  it("stops cleanly and does not reconnect", async () => {
    const { stream, sockets } = setup();
    stream.start();
    stream.stop();
    sockets[0]!.onclose?.({ code: 1000 });
    await new Promise((r) => setTimeout(r, 5));
    expect(sockets).toHaveLength(1);
    expect(sockets[0]!.closed).toBe(true);
  });
});
