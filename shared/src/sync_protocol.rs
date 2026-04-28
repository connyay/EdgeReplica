//! Wire types for the EdgeReplica sync WebSocket protocol.
//!
//! Each WebSocket binary frame is a single byte protocol version followed
//! by a [`SyncMessage`] serialized with MessagePack. The version byte lets
//! peers reject incompatible frames without paying the msgpack-decode cost.
//!
//! The enum is adjacently-tagged so a debugger or `msgpack-cli | jq` shows
//! `{"kind":"page_hash","data":{"page_no":42,"hash":"..."}}` instead of an
//! opaque integer discriminant.
//!
//! Page hashes are 32-byte BLAKE3 digests carried as `bytes::Bytes` (msgpack
//! `bin` format). BLAKE3 was chosen over SHA-256 because the worker runs in
//! wasm where SHA-256 has no hardware acceleration — the bench in
//! `bench/wasm-bench` measured BLAKE3 at ~5x SHA-256's wasm throughput.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Wire-protocol version. Bump when message semantics change in a way that
/// older peers can't parse — peers reject frames whose first byte does not
/// match this constant.
pub const PROTOCOL_VERSION: u8 = 1;

/// 32-byte BLAKE3 digest of a raw page. The hash is exchanged on the wire
/// (`SyncMessage::PageHash`) and stored alongside each page; both peers must
/// produce identical bytes for a given input, so this is the single source.
pub fn page_hash(data: &[u8]) -> Bytes {
    Bytes::copy_from_slice(blake3::hash(data).as_bytes())
}

/// Single envelope flowing in either direction over the sync WebSocket.
///
/// `Direction` (push vs pull) is *not* on the wire — it comes from the
/// verified sync macaroon at connect time. The same message types appear
/// in both directions; the FSM enforces which side may send what.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum SyncMessage {
    // ---------- Handshake ----------
    Hello {
        protocol_version: u32,
        page_size: u32,
        max_page: u32,
    },
    HelloReply {
        protocol_version: u32,
        page_size: u32,
        max_page: u32,
    },

    // ---------- Hash phase ----------
    /// 32-byte BLAKE3 digest of the raw page bytes.
    PageHash {
        page_no: u32,
        hash: Bytes,
    },
    /// Combined hash over a contiguous range — short-circuits when an
    /// entire range is identical between peers. 32-byte BLAKE3 digest
    /// over the concatenation of each page's hash, in page_no order.
    PageHashBatch {
        start_page: u32,
        end_page: u32,
        combined_hash: Bytes,
    },

    // ---------- Server-initiated requests for bytes ----------
    RequestPage {
        page_no: u32,
    },
    RequestPages {
        page_numbers: Vec<u32>,
    },

    // ---------- Server-initiated mismatch hints (pull) ----------
    HashMismatch {
        page_no: u32,
    },
    HashMismatchBatch {
        page_numbers: Vec<u32>,
    },

    // ---------- Page bytes ----------
    PageData {
        page_no: u32,
        data: Bytes,
    },
    PageDataBatch {
        pages: Vec<PageDataEntry>,
    },

    // ---------- Lifecycle ----------
    /// Client: "I've sent every hash I have." Server emits SyncComplete
    /// once any in-flight page requests resolve.
    Complete,
    SyncComplete {
        pages_transferred: u64,
        bytes_transferred: u64,
    },
    /// Fatal error. Connection should close after either peer sends or
    /// receives this.
    Error {
        message: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PageDataEntry {
    pub page_no: u32,
    pub data: Bytes,
}

/// Errors decoding a frame off the WebSocket.
#[derive(Debug, Error)]
pub enum FrameError {
    #[error("frame is empty (no version byte)")]
    Empty,
    #[error("protocol_version mismatch: this peer speaks {ours}, frame announced {theirs}")]
    VersionMismatch { ours: u8, theirs: u8 },
    #[error("msgpack decode: {0}")]
    Decode(String),
    #[error("msgpack encode: {0}")]
    Encode(String),
}

/// Encode a [`SyncMessage`] into a complete WebSocket binary frame.
pub fn encode_frame(msg: &SyncMessage) -> Result<Vec<u8>, FrameError> {
    let body = rmp_serde::to_vec_named(msg).map_err(|e| FrameError::Encode(e.to_string()))?;
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(PROTOCOL_VERSION);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decode a [`SyncMessage`] from a WebSocket binary frame. Verifies the
/// leading version byte; rejects mismatches without attempting to decode
/// the body.
pub fn decode_frame(frame: &[u8]) -> Result<SyncMessage, FrameError> {
    let &version = frame.first().ok_or(FrameError::Empty)?;
    if version != PROTOCOL_VERSION {
        return Err(FrameError::VersionMismatch {
            ours: PROTOCOL_VERSION,
            theirs: version,
        });
    }
    rmp_serde::from_slice::<SyncMessage>(&frame[1..]).map_err(|e| FrameError::Decode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(msg: SyncMessage) {
        let frame = encode_frame(&msg).expect("encode");
        assert_eq!(frame[0], PROTOCOL_VERSION);
        let back = decode_frame(&frame).expect("decode");
        assert_eq!(back, msg);
    }

    #[test]
    fn hello_roundtrips() {
        roundtrip(SyncMessage::Hello {
            protocol_version: 1,
            page_size: 4096,
            max_page: 1234,
        });
    }

    #[test]
    fn page_data_roundtrips_with_bytes() {
        roundtrip(SyncMessage::PageData {
            page_no: 7,
            data: Bytes::from(vec![0xAB; 4096]),
        });
    }

    #[test]
    fn page_data_batch_roundtrips() {
        roundtrip(SyncMessage::PageDataBatch {
            pages: vec![
                PageDataEntry {
                    page_no: 1,
                    data: Bytes::from_static(b"hello"),
                },
                PageDataEntry {
                    page_no: 2,
                    data: Bytes::from_static(b"world"),
                },
            ],
        });
    }

    #[test]
    fn page_hash_batch_roundtrips() {
        roundtrip(SyncMessage::PageHashBatch {
            start_page: 1,
            end_page: 100,
            combined_hash: Bytes::from_static(&[0xDE; 32]),
        });
    }

    #[test]
    fn page_hash_roundtrips() {
        roundtrip(SyncMessage::PageHash {
            page_no: 42,
            hash: Bytes::from_static(&[0xAB; 32]),
        });
    }

    #[test]
    fn complete_and_sync_complete_roundtrip() {
        roundtrip(SyncMessage::Complete);
        roundtrip(SyncMessage::SyncComplete {
            pages_transferred: 100,
            bytes_transferred: 100 * 4096,
        });
    }

    #[test]
    fn error_message_roundtrips() {
        roundtrip(SyncMessage::Error {
            message: "boom".into(),
        });
    }

    #[test]
    fn version_mismatch_rejected() {
        let mut frame = encode_frame(&SyncMessage::Complete).unwrap();
        frame[0] = 99;
        match decode_frame(&frame) {
            Err(FrameError::VersionMismatch {
                ours: 1,
                theirs: 99,
            }) => {}
            other => panic!("expected version mismatch, got {other:?}"),
        }
    }

    #[test]
    fn empty_frame_rejected() {
        match decode_frame(&[]) {
            Err(FrameError::Empty) => {}
            other => panic!("expected empty error, got {other:?}"),
        }
    }

    #[test]
    fn adjacent_tag_present_in_msgpack() {
        // Sanity check: the encoded frame contains the `kind` discriminator
        // string so a debugging tool can find it without knowing the schema.
        let frame = encode_frame(&SyncMessage::Complete).unwrap();
        let body = &frame[1..];
        // msgpack encodes "kind" as a fixstr; just check the substring is present.
        assert!(
            body.windows(4).any(|w| w == b"kind"),
            "expected 'kind' tag in body, got {body:?}",
        );
    }
}
