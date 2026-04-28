import { describe, it, expect } from "vitest";
import { blake3 } from "@noble/hashes/blake3.js";
import { Direction } from "../gen/edgereplica/admin/v1/admin_pb.js";
import { authedAdminClient } from "./helpers";
import { PROTOCOL_VERSION, type SyncMessage } from "./sync-frame";
import { type SyncSession, openSync } from "./sync-session";

const PAGE_SIZE = 4096;

// Build a synthetic page filled with one repeating byte. The FSM treats
// page bytes as opaque — what matters is that hashing is consistent
// between client and server (BLAKE3-256 in both).
function makePage(fill: number): Uint8Array {
  return new Uint8Array(PAGE_SIZE).fill(fill);
}

function pageHash(data: Uint8Array): Uint8Array {
  return blake3(data);
}

interface SyncDb {
  databaseId: string;
  pushToken: string;
  pullToken: string;
}

async function provisionDatabase(name: string): Promise<SyncDb> {
  const { client } = await authedAdminClient();
  const db = await client.createDatabase({ name });
  const [push, pull] = await Promise.all([
    client.issueSyncToken({
      databaseId: db.id,
      direction: Direction.PUSH,
      ttlSeconds: 60n,
    }),
    client.issueSyncToken({
      databaseId: db.id,
      direction: Direction.PULL,
      ttlSeconds: 60n,
    }),
  ]);
  return { databaseId: db.id, pushToken: push.token, pullToken: pull.token };
}

async function handshake(s: SyncSession): Promise<number> {
  s.send({
    kind: "hello",
    data: {
      protocol_version: PROTOCOL_VERSION,
      page_size: PAGE_SIZE,
      max_page: 0,
    },
  });
  const reply = await s.recv();
  if (reply.kind !== "hello_reply") {
    throw new Error(`expected hello_reply, got ${reply.kind}`);
  }
  return reply.data.max_page;
}

// Drive the typical push flow: announce hashes for each page; respond to
// every RequestPage with the corresponding bytes; send Complete; collect
// frames through SyncComplete.
async function push(
  s: SyncSession,
  pages: Map<number, Uint8Array>,
): Promise<{ pagesTransferred: number; bytesTransferred: number }> {
  await handshake(s);
  for (const [pageNo, data] of pages) {
    s.send({
      kind: "page_hash",
      data: { page_no: pageNo, hash: pageHash(data) },
    });
  }
  s.send({ kind: "complete" });

  let result: {
    pagesTransferred: number;
    bytesTransferred: number;
  } | null = null;
  while (!result) {
    const m = await s.recv();
    if (m.kind === "request_page") {
      const data = pages.get(m.data.page_no);
      if (!data) throw new Error(`server requested unknown page ${m.data.page_no}`);
      s.send({ kind: "page_data", data: { page_no: m.data.page_no, data } });
    } else if (m.kind === "sync_complete") {
      result = {
        pagesTransferred: m.data.pages_transferred,
        bytesTransferred: m.data.bytes_transferred,
      };
    } else if (m.kind === "error") {
      throw new Error(`server error: ${m.data.message}`);
    } else {
      throw new Error(`unexpected frame in push: ${m.kind}`);
    }
  }
  return result;
}

describe("sync push", () => {
  it("uploads pages from a fresh client into an empty DO", async () => {
    const db = await provisionDatabase("push-fresh");
    const s = await openSync(db.pushToken);

    const pages = new Map<number, Uint8Array>([
      [1, makePage(0xa1)],
      [2, makePage(0xa2)],
      [3, makePage(0xa3)],
    ]);

    const result = await push(s, pages);
    expect(result.pagesTransferred).toBe(3);
    expect(result.bytesTransferred).toBe(PAGE_SIZE * pages.size);
  });

  it("skips pages whose hash already matches (no RequestPage)", async () => {
    const db = await provisionDatabase("push-dedup");
    const pages = new Map<number, Uint8Array>([
      [1, makePage(0xb1)],
      [2, makePage(0xb2)],
    ]);

    // First sync: full upload.
    await push(await openSync(db.pushToken), pages);

    // Second sync with the same bytes: server already has matching hashes,
    // should ask for nothing and SyncComplete with zero transferred.
    const s = await openSync(db.pushToken);
    const result = await push(s, pages);
    expect(result.pagesTransferred).toBe(0);
    expect(result.bytesTransferred).toBe(0);
  });
});

describe("sync pull", () => {
  it("downloads every page from a seeded DO when client claims none", async () => {
    const db = await provisionDatabase("pull-empty-client");
    const seed = new Map<number, Uint8Array>([
      [1, makePage(0xc1)],
      [2, makePage(0xc2)],
      [3, makePage(0xc3)],
    ]);
    await push(await openSync(db.pushToken), seed);

    const s = await openSync(db.pullToken);
    const serverMax = await handshake(s);
    expect(serverMax).toBe(3);

    // No PageHash from the client → server must walk pages 1..max on Complete.
    s.send({ kind: "complete" });
    const frames = await s.recvUntil((m) => m.kind === "sync_complete");

    const received = new Map<number, Uint8Array>();
    for (const m of frames) {
      if (m.kind === "page_data") {
        received.set(m.data.page_no, m.data.data);
      }
    }
    expect([...received.keys()].sort()).toEqual([1, 2, 3]);
    for (const [pageNo, data] of seed) {
      expect(received.get(pageNo)).toEqual(data);
    }

    const tail = frames[frames.length - 1] as Extract<
      SyncMessage,
      { kind: "sync_complete" }
    >;
    expect(tail.data.pages_transferred).toBe(3);
    expect(tail.data.bytes_transferred).toBe(PAGE_SIZE * seed.size);
  });

  it("skips matching pages and streams only the mismatches", async () => {
    const db = await provisionDatabase("pull-partial");
    const seed = new Map<number, Uint8Array>([
      [1, makePage(0xd1)],
      [2, makePage(0xd2)],
      [3, makePage(0xd3)],
    ]);
    await push(await openSync(db.pushToken), seed);

    const s = await openSync(db.pullToken);
    await handshake(s);

    // Client claims page 2 with the matching hash, page 3 with a wrong
    // one. Page 1 is not announced — server should still send it after
    // Complete (the "client never had page 1" path).
    s.send({
      kind: "page_hash",
      data: { page_no: 2, hash: pageHash(seed.get(2)!) },
    });
    s.send({
      kind: "page_hash",
      data: { page_no: 3, hash: new Uint8Array(32) },
    });
    s.send({ kind: "complete" });

    const frames = await s.recvUntil((m) => m.kind === "sync_complete");
    const received = new Map<number, Uint8Array>();
    for (const m of frames) {
      if (m.kind === "page_data") received.set(m.data.page_no, m.data.data);
    }

    expect([...received.keys()].sort()).toEqual([1, 3]);
    expect(received.get(1)).toEqual(seed.get(1));
    expect(received.get(3)).toEqual(seed.get(3));
  });
});
