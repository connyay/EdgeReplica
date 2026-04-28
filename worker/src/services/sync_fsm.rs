//! Transport-agnostic sync FSM. Drives the per-connection state machine
//! that the WebSocket handler in [`crate::do_sync_ws`] runs against
//! [`SyncStorage`]. Operates on [`SyncMessage`] frames in both
//! directions; the WebSocket layer just plumbs frames in and emits
//! whatever the FSM returns.
//!
//! Direction (push vs pull) is set at construction from the verified
//! sync macaroon — the FSM enforces who may send what.
//!
//! `SyncComplete` is emitted at most once: handlers route through
//! `maybe_emit_complete`, which short-circuits when `emitted_complete`
//! is already set. Multiple triggers (last `PageData`, `Complete`, peer
//! close) can each independently satisfy the emit predicate.

use std::collections::HashSet;
use std::sync::Arc;

use edgereplica_protocol::sync::{PROTOCOL_VERSION as SYNC_PROTOCOL_VERSION, SyncMessage};

use crate::clock::SharedClock;
use crate::domain::Direction;
use crate::error::StoreError;

use crate::services::sync_storage::{SyncStorage, page_hash};

/// Sink the FSM hands each outbound frame to. Returning `Err` aborts the
/// current `apply` call (e.g. the WebSocket send failed); the FSM does not
/// retry or buffer.
pub type Emit<'a> = &'a mut dyn FnMut(SyncMessage) -> Result<(), String>;

/// Wire-protocol version carried in the [`SyncMessage::Hello`] handshake.
/// Same value as the frame-byte [`SYNC_PROTOCOL_VERSION`], widened to the
/// `u32` field on the message.
const HANDSHAKE_VERSION: u32 = SYNC_PROTOCOL_VERSION as u32;

/// One sync session's worth of state.
pub struct SyncFsm<S: SyncStorage + Send + Sync + 'static> {
    storage: Arc<S>,
    clock: SharedClock,
    direction: Direction,
    saw_hello: bool,
    completed_hash_phase: bool,
    pending_requests: HashSet<u32>,
    /// Page numbers the client claims to have. Populated from inbound
    /// `PageHash` frames. Used in pull to skip pages the client already
    /// has (matching hash) or has been served inline (mismatching hash);
    /// any server page NOT in this set on `Complete` is sent fresh.
    client_seen: HashSet<u32>,
    /// Cached snapshot of the storage's `max_page()` taken at handshake
    /// time. Storage is single-writer within a session, so the value is
    /// stable for the duration of the FSM and we don't need to re-query
    /// on `Complete`.
    server_max_page: u32,
    pages_transferred: u64,
    bytes_transferred: u64,
    emitted_complete: bool,
}

impl<S: SyncStorage + Send + Sync + 'static> SyncFsm<S> {
    pub fn new(storage: Arc<S>, clock: SharedClock, direction: Direction) -> Self {
        Self {
            storage,
            clock,
            direction,
            saw_hello: false,
            completed_hash_phase: false,
            pending_requests: HashSet::new(),
            client_seen: HashSet::new(),
            server_max_page: 0,
            pages_transferred: 0,
            bytes_transferred: 0,
            emitted_complete: false,
        }
    }

    /// Drive one inbound message through the FSM, streaming any outbound
    /// frames into `emit` in order. The callback is invoked once per frame
    /// and may ship the frame immediately, so the FSM never buffers more
    /// than one outbound message at a time — this is what keeps a pull of
    /// a multi-GB DB from holding every page in worker RAM.
    pub fn apply(&mut self, msg: &SyncMessage, emit: Emit<'_>) -> Result<(), String> {
        if !self.saw_hello {
            return match msg {
                SyncMessage::Hello {
                    protocol_version,
                    page_size,
                    ..
                } => self.handle_hello(*protocol_version, *page_size, emit),
                _ => Err("first message must be Hello".into()),
            };
        }

        match msg {
            SyncMessage::Hello { .. } => Err("Hello may only be sent once".into()),
            SyncMessage::PageHash { page_no, hash } => self.handle_page_hash(*page_no, hash, emit),
            SyncMessage::PageHashBatch {
                start_page,
                end_page,
                combined_hash: ch,
            } => self.handle_page_hash_batch(*start_page, *end_page, ch, emit),
            SyncMessage::PageData { page_no, data } => {
                self.handle_page_data(*page_no, data.as_ref(), emit)
            }
            SyncMessage::PageDataBatch { pages } => {
                for entry in pages {
                    self.handle_page_data(entry.page_no, entry.data.as_ref(), emit)?;
                }
                Ok(())
            }
            SyncMessage::Complete => self.handle_complete(emit),

            SyncMessage::HelloReply { .. }
            | SyncMessage::RequestPage { .. }
            | SyncMessage::RequestPages { .. }
            | SyncMessage::HashMismatch { .. }
            | SyncMessage::HashMismatchBatch { .. }
            | SyncMessage::SyncComplete { .. }
            | SyncMessage::Error { .. } => {
                Err("client may not send server-originated message".into())
            }
        }
    }

    /// Called when the client side of the WebSocket closes (clean or
    /// otherwise). Marks the FSM as done if the predicate fits; the
    /// closed transport means we can't actually deliver anything, so
    /// no messages are emitted.
    pub fn client_closed(&mut self) {
        if self.saw_hello && self.pending_requests.is_empty() {
            let _ = self.maybe_emit_complete(&mut |_| Ok(()));
        }
    }

    /// True once the FSM has emitted SyncComplete. The handler uses this
    /// to decide when to close the WebSocket cleanly.
    pub fn done(&self) -> bool {
        self.emitted_complete
    }

    // ----- handlers -----

    fn handle_hello(
        &mut self,
        protocol_version: u32,
        page_size: u32,
        emit: Emit<'_>,
    ) -> Result<(), String> {
        if protocol_version != HANDSHAKE_VERSION {
            return Err(format!(
                "protocol_version mismatch: server={HANDSHAKE_VERSION}, client={protocol_version}"
            ));
        }
        self.saw_hello = true;
        self.server_max_page = self.storage.max_page().map_err(|e| e.to_string())?;
        emit(SyncMessage::HelloReply {
            protocol_version: HANDSHAKE_VERSION,
            page_size,
            max_page: self.server_max_page,
        })
    }

    fn handle_page_hash(
        &mut self,
        page_no: u32,
        hash: &[u8],
        emit: Emit<'_>,
    ) -> Result<(), String> {
        // Record that the client claims this page so the post-`Complete`
        // walk in pull doesn't re-send it.
        self.client_seen.insert(page_no);

        let stored = self
            .storage
            .get_page_hash(page_no)
            .map_err(|e| e.to_string())?;
        if stored.as_deref() == Some(hash) {
            return Ok(());
        }
        match self.direction {
            Direction::Push => {
                self.pending_requests.insert(page_no);
                emit(SyncMessage::RequestPage { page_no })
            }
            Direction::Pull => {
                if let Some(data) = self.storage.get_page(page_no).map_err(|e| e.to_string())? {
                    self.bytes_transferred += data.len() as u64;
                    self.pages_transferred += 1;
                    emit(SyncMessage::PageData { page_no, data })?;
                }
                Ok(())
            }
        }
    }

    fn handle_page_hash_batch(
        &mut self,
        start_page: u32,
        end_page: u32,
        client_combined: &[u8],
        emit: Emit<'_>,
    ) -> Result<(), String> {
        let stored = self
            .storage
            .combined_hash(start_page, end_page)
            .map_err(|e| e.to_string())?;
        if stored.as_ref() == client_combined {
            return Ok(());
        }
        let page_numbers: Vec<u32> = (start_page..=end_page).collect();
        emit(SyncMessage::HashMismatchBatch { page_numbers })
    }

    fn handle_page_data(
        &mut self,
        page_no: u32,
        data: &[u8],
        emit: Emit<'_>,
    ) -> Result<(), String> {
        self.pending_requests.remove(&page_no);
        let hash = page_hash(data);
        let now = self.clock.now_ms();
        self.storage
            .put_page(page_no, data, &hash, now)
            .map_err(|e| e.to_string())?;
        self.pages_transferred += 1;
        self.bytes_transferred += data.len() as u64;

        self.maybe_emit_complete(emit)
    }

    fn handle_complete(&mut self, emit: Emit<'_>) -> Result<(), String> {
        self.completed_hash_phase = true;

        // Pull only: stream any page the client didn't claim. Pages the
        // client *did* claim were already handled inline in
        // `handle_page_hash` (matched ones skipped, mismatched ones sent).
        // The cursor in `iter_pages_in_range` yields one page at a time
        // and `emit` ships each frame before the next row is decoded, so
        // the walk runs in bounded RAM regardless of DB size.
        if matches!(self.direction, Direction::Pull) && self.server_max_page > 0 {
            // Take a fresh handle so the storage borrow doesn't conflict
            // with the closure's access to `&mut self`.
            let storage = Arc::clone(&self.storage);
            // The closure threads its own `String` error out via this slot
            // because `iter_pages_in_range`'s callback signature speaks
            // `StoreError`; we want to surface the raw send-failure string.
            let mut emit_err: Option<String> = None;
            let result =
                storage.iter_pages_in_range(1, self.server_max_page, &mut |page_no, data| {
                    if self.client_seen.contains(&page_no) {
                        return Ok(());
                    }
                    self.bytes_transferred += data.len() as u64;
                    self.pages_transferred += 1;
                    if let Err(e) = emit(SyncMessage::PageData { page_no, data }) {
                        emit_err = Some(e);
                        // Bail out of the cursor immediately.
                        return Err(StoreError::backend("emit aborted"));
                    }
                    Ok(())
                });
            if let Some(e) = emit_err {
                return Err(e);
            }
            result.map_err(|e| e.to_string())?;
        }

        self.maybe_emit_complete(emit)
    }

    /// Single emission gate. Only emits SyncComplete if we haven't
    /// already, the client has finished its hash phase, and we're not
    /// waiting on any page bytes.
    fn maybe_emit_complete(&mut self, emit: Emit<'_>) -> Result<(), String> {
        if self.emitted_complete || !self.completed_hash_phase || !self.pending_requests.is_empty()
        {
            return Ok(());
        }
        emit(SyncMessage::SyncComplete {
            pages_transferred: self.pages_transferred,
            bytes_transferred: self.bytes_transferred,
        })?;
        self.emitted_complete = true;
        Ok(())
    }
}

// =================== Tests ===================

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bytes::Bytes;
    use edgereplica_protocol::sync::SyncMessage;

    use crate::clock::{FixedClock, SharedClock};
    use crate::domain::Direction;

    use crate::services::sync_storage::{InMemorySyncStorage, SyncStorage, page_hash};

    use super::{HANDSHAKE_VERSION, SyncFsm};

    fn page_hash_msg(page_no: u32, hash: Bytes) -> SyncMessage {
        SyncMessage::PageHash { page_no, hash }
    }

    fn fsm(
        direction: Direction,
        storage: Arc<InMemorySyncStorage>,
    ) -> SyncFsm<InMemorySyncStorage> {
        let clock: SharedClock = FixedClock::new(1_700_000_000_000);
        SyncFsm::new(storage, clock, direction)
    }

    fn hello() -> SyncMessage {
        SyncMessage::Hello {
            protocol_version: HANDSHAKE_VERSION,
            page_size: 4096,
            max_page: 0,
        }
    }

    fn page_data_msg(page_no: u32, data: Vec<u8>) -> SyncMessage {
        SyncMessage::PageData {
            page_no,
            data: Bytes::from(data),
        }
    }

    fn drive(f: &mut SyncFsm<InMemorySyncStorage>, inputs: Vec<SyncMessage>) -> Vec<SyncMessage> {
        let mut out = Vec::new();
        for input in inputs {
            f.apply(&input, &mut |m| {
                out.push(m);
                Ok(())
            })
            .expect("apply ok");
        }
        f.client_closed();
        out
    }

    #[test]
    fn empty_push_yields_hello_reply_and_sync_complete() {
        let storage = Arc::new(InMemorySyncStorage::new());
        let mut f = fsm(Direction::Push, Arc::clone(&storage));
        let out = drive(&mut f, vec![hello(), SyncMessage::Complete]);
        assert!(matches!(out[0], SyncMessage::HelloReply { .. }));
        match &out[1] {
            SyncMessage::SyncComplete {
                pages_transferred,
                bytes_transferred,
            } => {
                assert_eq!(*pages_transferred, 0);
                assert_eq!(*bytes_transferred, 0);
            }
            other => panic!("expected SyncComplete, got {other:?}"),
        }
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn push_unknown_page_triggers_request_then_stores_data() {
        let storage = Arc::new(InMemorySyncStorage::new());
        let mut f = fsm(Direction::Push, Arc::clone(&storage));
        let data = vec![0xAB; 4096];
        let h = page_hash(&data);
        let out = drive(
            &mut f,
            vec![
                hello(),
                page_hash_msg(1, h.clone()),
                page_data_msg(1, data.clone()),
                SyncMessage::Complete,
            ],
        );
        assert!(matches!(out[0], SyncMessage::HelloReply { .. }));
        match &out[1] {
            SyncMessage::RequestPage { page_no: 1 } => {}
            other => panic!("expected RequestPage(1), got {other:?}"),
        }
        match &out[2] {
            SyncMessage::SyncComplete {
                pages_transferred: 1,
                bytes_transferred: 4096,
            } => {}
            other => panic!("expected SyncComplete(1, 4096), got {other:?}"),
        }
        assert_eq!(out.len(), 3);
        assert_eq!(storage.get_page(1).unwrap(), Some(Bytes::from(data)));
    }

    #[test]
    fn push_matching_hash_skips_request() {
        let storage = Arc::new(InMemorySyncStorage::new());
        let data = vec![0xCD; 4096];
        let h = page_hash(&data);
        storage.put_page(1, &data, &h, 0).unwrap();

        let mut f = fsm(Direction::Push, Arc::clone(&storage));
        let out = drive(
            &mut f,
            vec![hello(), page_hash_msg(1, h.clone()), SyncMessage::Complete],
        );
        // HelloReply then SyncComplete; no RequestPage in between.
        assert_eq!(out.len(), 2);
        assert!(matches!(out[1], SyncMessage::SyncComplete { .. }));
    }

    #[test]
    fn pull_mismatch_streams_page_data() {
        let storage = Arc::new(InMemorySyncStorage::new());
        storage.put_page(1, b"old", &page_hash(b"old"), 0).unwrap();

        let mut f = fsm(Direction::Pull, Arc::clone(&storage));
        let out = drive(
            &mut f,
            vec![
                hello(),
                page_hash_msg(1, page_hash(b"new")),
                SyncMessage::Complete,
            ],
        );
        assert_eq!(out.len(), 3);
        assert!(matches!(out[0], SyncMessage::HelloReply { .. }));
        match &out[1] {
            SyncMessage::PageData { page_no: 1, data } => assert_eq!(data.as_ref(), b"old"),
            other => panic!("expected PageData(1), got {other:?}"),
        }
        match &out[2] {
            SyncMessage::SyncComplete {
                pages_transferred: 1,
                bytes_transferred: 3,
            } => {}
            other => panic!("expected SyncComplete(1, 3), got {other:?}"),
        }
    }

    #[test]
    fn pull_into_empty_client_streams_every_server_page() {
        // The reported regression: fresh local DB has zero pages, so the
        // client sends zero PageHash frames. Server must walk its own
        // pages and ship them all on Complete.
        let storage = Arc::new(InMemorySyncStorage::new());
        for p in 1u32..=3 {
            let data = vec![p as u8; 4096];
            let h = page_hash(&data);
            storage.put_page(p, &data, &h, 0).unwrap();
        }

        let mut f = fsm(Direction::Pull, Arc::clone(&storage));
        let out = drive(&mut f, vec![hello(), SyncMessage::Complete]);

        assert!(matches!(out[0], SyncMessage::HelloReply { .. }));
        let page_nos: Vec<u32> = out
            .iter()
            .filter_map(|m| match m {
                SyncMessage::PageData { page_no, .. } => Some(*page_no),
                _ => None,
            })
            .collect();
        assert_eq!(page_nos, vec![1, 2, 3]);
        match out.last().unwrap() {
            SyncMessage::SyncComplete {
                pages_transferred: 3,
                bytes_transferred: 12288,
            } => {}
            other => panic!("expected SyncComplete(3, 12288), got {other:?}"),
        }
    }

    #[test]
    fn pull_skips_pages_client_already_has() {
        // Server has pages 1..=3. Client already has page 2 with the
        // matching hash, and page 3 with a different hash. Server should
        // send only pages 1 (client missing) and 3 (mismatch) — not 2.
        let storage = Arc::new(InMemorySyncStorage::new());
        let p1 = vec![1u8; 4096];
        let p2 = vec![2u8; 4096];
        let p3 = vec![3u8; 4096];
        storage.put_page(1, &p1, &page_hash(&p1), 0).unwrap();
        storage.put_page(2, &p2, &page_hash(&p2), 0).unwrap();
        storage.put_page(3, &p3, &page_hash(&p3), 0).unwrap();

        let mut f = fsm(Direction::Pull, Arc::clone(&storage));
        let out = drive(
            &mut f,
            vec![
                hello(),
                page_hash_msg(2, page_hash(&p2)),    // matches
                page_hash_msg(3, page_hash(b"old")), // mismatch
                SyncMessage::Complete,
            ],
        );

        let page_nos: Vec<u32> = out
            .iter()
            .filter_map(|m| match m {
                SyncMessage::PageData { page_no, .. } => Some(*page_no),
                _ => None,
            })
            .collect();
        assert_eq!(
            page_nos,
            vec![3, 1],
            "page 3 inline (mismatch), page 1 on complete (missing)"
        );
    }

    #[test]
    fn pull_matching_hash_emits_nothing_extra() {
        let storage = Arc::new(InMemorySyncStorage::new());
        let data = vec![0xEE; 4096];
        let h = page_hash(&data);
        storage.put_page(1, &data, &h, 0).unwrap();

        let mut f = fsm(Direction::Pull, Arc::clone(&storage));
        let out = drive(
            &mut f,
            vec![hello(), page_hash_msg(1, h.clone()), SyncMessage::Complete],
        );
        assert_eq!(out.len(), 2);
        assert!(matches!(out[1], SyncMessage::SyncComplete { .. }));
    }

    #[test]
    fn first_message_must_be_hello() {
        let storage = Arc::new(InMemorySyncStorage::new());
        let mut f = fsm(Direction::Push, Arc::clone(&storage));
        let err = f
            .apply(
                &page_hash_msg(1, Bytes::from_static(&[0xDE; 32])),
                &mut |_| Ok(()),
            )
            .unwrap_err();
        assert!(err.contains("Hello"), "got {err}");
    }

    #[test]
    fn protocol_version_mismatch_rejected() {
        let storage = Arc::new(InMemorySyncStorage::new());
        let mut f = fsm(Direction::Push, Arc::clone(&storage));
        let err = f
            .apply(
                &SyncMessage::Hello {
                    protocol_version: 999,
                    page_size: 4096,
                    max_page: 0,
                },
                &mut |_| Ok(()),
            )
            .unwrap_err();
        assert!(err.contains("protocol_version mismatch"), "got {err}");
    }

    #[test]
    fn sync_complete_emitted_at_most_once() {
        // Race shape: the last PageData arrives, marking
        // pending_requests empty, BEFORE the client's Complete frame
        // does. The data handler triggers maybe_emit_complete (no-op
        // because completed_hash_phase=false), then Complete fires
        // maybe_emit_complete a second time (which DOES emit). The
        // single-emission gate must still cap output at one
        // SyncComplete across the conversation.
        let storage = Arc::new(InMemorySyncStorage::new());
        let mut f = fsm(Direction::Push, Arc::clone(&storage));
        let data = vec![0x11; 4096];
        let h = page_hash(&data);
        let out = drive(
            &mut f,
            vec![
                hello(),
                page_hash_msg(1, h.clone()),
                page_data_msg(1, data),
                SyncMessage::Complete,
                // Extra Complete to try to force a duplicate.
                SyncMessage::Complete,
            ],
        );
        let count = out
            .iter()
            .filter(|m| matches!(m, SyncMessage::SyncComplete { .. }))
            .count();
        assert_eq!(count, 1, "expected exactly one SyncComplete, got: {out:?}");
        assert!(f.done());
    }

    #[test]
    fn client_close_without_complete_emits_nothing_extra() {
        // Push direction: client opens the stream, sends Hello, then
        // disconnects. We've never seen Complete, so we shouldn't emit
        // a SyncComplete (the half-finished sync isn't successful).
        let storage = Arc::new(InMemorySyncStorage::new());
        let mut f = fsm(Direction::Push, Arc::clone(&storage));
        let mut out = Vec::new();
        f.apply(&hello(), &mut |m| {
            out.push(m);
            Ok(())
        })
        .unwrap();
        f.client_closed();
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], SyncMessage::HelloReply { .. }));
        assert!(!f.done());
    }
}
