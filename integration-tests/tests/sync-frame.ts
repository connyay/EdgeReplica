// MessagePack framing for sync — mirrors `shared/src/sync_protocol.rs`.
// Wire format: 1 version byte (PROTOCOL_VERSION) + msgpack(SyncMessage),
// where SyncMessage is serde-tagged as { kind: "<snake_case>", data: {...} }.

import { decode, encode } from "@msgpack/msgpack";

export const PROTOCOL_VERSION = 1;

// Discriminated union, kind/data shape matching the Rust enum. Only the
// variants the integration tests actually drive are listed here; add more
// as tests need them.
export type SyncMessage =
  | { kind: "hello"; data: HelloData }
  | { kind: "hello_reply"; data: HelloData }
  | { kind: "page_hash"; data: { page_no: number; hash: Uint8Array } }
  | { kind: "request_page"; data: { page_no: number } }
  | { kind: "page_data"; data: { page_no: number; data: Uint8Array } }
  | { kind: "complete" }
  // u64 on the wire, but @msgpack/msgpack decodes integers within
  // Number.MAX_SAFE_INTEGER as Number. Tests stay well within that range.
  | {
      kind: "sync_complete";
      data: { pages_transferred: number; bytes_transferred: number };
    }
  | { kind: "error"; data: { message: string } };

export interface HelloData {
  protocol_version: number;
  page_size: number;
  max_page: number;
}

// Returns a Uint8Array<ArrayBuffer> (not <ArrayBufferLike>) so it satisfies
// WebSocket.send's signature without a cast.
export function encodeFrame(msg: SyncMessage): Uint8Array<ArrayBuffer> {
  const body = encode(msg);
  const buf = new ArrayBuffer(1 + body.byteLength);
  const out = new Uint8Array(buf);
  out[0] = PROTOCOL_VERSION;
  out.set(body, 1);
  return out;
}

export function decodeFrame(frame: Uint8Array): SyncMessage {
  if (frame.byteLength === 0) throw new Error("empty frame");
  if (frame[0] !== PROTOCOL_VERSION) {
    throw new Error(
      `protocol_version mismatch: ours=${PROTOCOL_VERSION}, theirs=${frame[0]}`,
    );
  }
  return decode(frame.subarray(1)) as SyncMessage;
}
