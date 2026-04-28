import { describe, it, expect } from "vitest";
import { Direction } from "../gen/edgereplica/admin/v1/admin_pb.js";
import { mf, mfUrl } from "./mf";
import { authedAdminClient } from "./helpers";
import { PROTOCOL_VERSION } from "./sync-frame";
import { openSync } from "./sync-session";

const PAGE_SIZE = 4096;

// Spike: confirm Miniflare proxies a WebSocket upgrade through the
// EdgeReplica DurableObject, and that the FSM responds to Hello with
// HelloReply. If this passes, push/pull (sync-push-pull.test.ts) can
// build on the same transport path.
describe("sync WebSocket handshake", () => {
  it("upgrades through the worker → DO and replies to Hello", async () => {
    const { client } = await authedAdminClient();
    const db = await client.createDatabase({ name: "syncprobe" });
    const tok = await client.issueSyncToken({
      databaseId: db.id,
      direction: Direction.PUSH,
      ttlSeconds: 60n,
    });

    const session = await openSync(tok.token);
    session.send({
      kind: "hello",
      data: {
        protocol_version: PROTOCOL_VERSION,
        page_size: PAGE_SIZE,
        max_page: 0,
      },
    });
    const reply = await session.recv();

    expect(reply.kind).toBe("hello_reply");
    if (reply.kind !== "hello_reply") throw new Error("type guard");
    expect(reply.data.protocol_version).toBe(PROTOCOL_VERSION);
    expect(reply.data.page_size).toBe(PAGE_SIZE);
    // Empty DB on the DO side → server's max_page is 0.
    expect(reply.data.max_page).toBe(0);

    session.close();
  });

  it("rejects upgrade without an Authorization header", async () => {
    const upgrade = await mf.dispatchFetch(`${mfUrl}/sync`, {
      headers: { Upgrade: "websocket" },
    });
    expect(upgrade.status).toBeGreaterThanOrEqual(400);
    expect(upgrade.status).toBeLessThan(500);
  });
});
