// Thin async wrapper over Miniflare's WebSocket for sync tests. Buffers
// incoming frames so `recv()` can be awaited even when frames arrive
// before the caller is ready to read them.

import { mf, mfUrl } from "./mf";
import { type SyncMessage, decodeFrame, encodeFrame } from "./sync-frame";

export interface SyncSession {
  send(msg: SyncMessage): void;
  recv(): Promise<SyncMessage>;
  /** Drain frames until SyncComplete (or matcher returns true). */
  recvUntil(matcher: (m: SyncMessage) => boolean): Promise<SyncMessage[]>;
  close(code?: number, reason?: string): void;
}

interface Pending {
  resolve: (msg: SyncMessage) => void;
  reject: (err: Error) => void;
}

export async function openSync(token: string): Promise<SyncSession> {
  const upgrade = await mf.dispatchFetch(`${mfUrl}/sync`, {
    headers: {
      Upgrade: "websocket",
      Authorization: `Bearer ${token}`,
    },
  });
  if (upgrade.status !== 101) {
    throw new Error(`sync upgrade failed: ${upgrade.status}`);
  }
  const { webSocket } = upgrade;
  if (!webSocket) throw new Error("expected webSocket on 101 response");
  webSocket.accept();

  const queue: SyncMessage[] = [];
  const waiters: Pending[] = [];
  let closeError: Error | null = null;

  const failAll = (err: Error) => {
    closeError = err;
    while (waiters.length) waiters.shift()!.reject(err);
  };

  webSocket.addEventListener("message", ((event: MessageEvent) => {
    const data = event.data;
    const bytes =
      data instanceof ArrayBuffer
        ? new Uint8Array(data)
        : data instanceof Uint8Array
          ? data
          : null;
    if (!bytes) {
      failAll(new Error(`unexpected frame type: ${typeof data}`));
      return;
    }
    let msg: SyncMessage;
    try {
      msg = decodeFrame(bytes);
    } catch (e) {
      failAll(e instanceof Error ? e : new Error(String(e)));
      return;
    }
    const waiter = waiters.shift();
    if (waiter) waiter.resolve(msg);
    else queue.push(msg);
  }) as EventListener);

  webSocket.addEventListener("close", ((event: CloseEvent) => {
    // Code 1000 with "sync complete" is a clean server-side close after
    // SyncComplete has already been delivered. Pending recv()s after that
    // are programming errors, not transport failures.
    failAll(
      new Error(`ws closed: code=${event.code} reason=${event.reason || ""}`),
    );
  }) as EventListener);

  webSocket.addEventListener("error", () => failAll(new Error("ws error")));

  const recv = (): Promise<SyncMessage> => {
    if (queue.length) return Promise.resolve(queue.shift()!);
    if (closeError) return Promise.reject(closeError);
    return new Promise<SyncMessage>((resolve, reject) =>
      waiters.push({ resolve, reject }),
    );
  };

  const session: SyncSession = {
    send(msg) {
      webSocket.send(encodeFrame(msg));
    },
    recv,
    async recvUntil(matcher) {
      const out: SyncMessage[] = [];
      while (true) {
        const m = await recv();
        out.push(m);
        if (matcher(m)) return out;
      }
    },
    close(code = 1000, reason = "test done") {
      webSocket.close(code, reason);
    },
  };
  return session;
}
