//! `edgereplica.sync.v1.SyncService` implementation. Hosted **inside** the
//! EdgeReplica DurableObject so the FSM lives next to the SqlStorage it
//! reads/writes.
//!
//! The handler is a `futures::stream::unfold` over a state struct: each
//! poll either drains a queued outbound envelope or reads the next
//! request and routes it through `process_envelope`. That keeps the
//! state in one place (vs v1's per-handler thread-of-mutation) and
//! means `process_envelope` can be exercised on the host with an
//! `InMemorySyncStorage`.
//!
//! Direction (push vs pull) comes from the verified sync macaroon in
//! `RpcContext::extensions`. The FSM trusts that — there is no ambient
//! "current direction" to second-guess.

use std::collections::{HashSet, VecDeque};
use std::pin::Pin;
use std::sync::Arc;

use buffa::view::OwnedView;
use connectrpc::{ConnectError, Context as RpcContext};
use edgereplica_protocol::sync::v1::{
    ClientEnvelopeView, HashMismatchBatch, HelloReply, PageData, PageDataBatchView,
    PageHashBatchView, RequestPage, ServerEnvelope, SyncComplete, SyncError, SyncService,
    client_envelope::PayloadView, server_envelope::Payload as ServerPayload,
};
use edgereplica_shared::{Direction, SharedClock, SyncContext};
use futures::{Stream, StreamExt as _};

use crate::middleware::require_sync;
use crate::services::sync_storage::{SyncStorage, combined_hash, page_hash};

/// Wire protocol version. Bump when FSM semantics change in a way
/// older clients can't parse.
pub const PROTOCOL_VERSION: u32 = 1;

/// Non-async data the FSM threads through `unfold`. Holds the request
/// stream, the storage handle, the verified direction, and the
/// running stats. `pending_outgoing` lets a single request emit
/// multiple responses (e.g. RequestPages → many PageData).
struct FsmState<S: SyncStorage + Send + Sync + 'static> {
    storage: Arc<S>,
    clock: SharedClock,
    direction: Direction,
    saw_hello: bool,
    completed_hash_phase: bool,
    pending_requests: HashSet<u32>,
    pages_transferred: u64,
    bytes_transferred: u64,
    pending_outgoing: VecDeque<ServerEnvelope>,
    finished: bool,
    requests: Pin<
        Box<dyn Stream<Item = Result<OwnedView<ClientEnvelopeView<'static>>, ConnectError>> + Send>,
    >,
}

pub struct SyncServer<S: SyncStorage + Send + Sync + 'static> {
    storage: Arc<S>,
    clock: SharedClock,
}

impl<S: SyncStorage + Send + Sync + 'static> SyncServer<S> {
    pub fn new(storage: Arc<S>, clock: SharedClock) -> Self {
        Self { storage, clock }
    }
}

impl<S: SyncStorage + Send + Sync + 'static> SyncService for SyncServer<S> {
    async fn sync(
        &self,
        ctx: RpcContext,
        requests: Pin<
            Box<
                dyn Stream<Item = Result<OwnedView<ClientEnvelopeView<'static>>, ConnectError>>
                    + Send,
            >,
        >,
    ) -> Result<
        (
            Pin<Box<dyn Stream<Item = Result<ServerEnvelope, ConnectError>> + Send>>,
            RpcContext,
        ),
        ConnectError,
    > {
        let sync_ctx: SyncContext = require_sync(&ctx)?;
        let state = FsmState {
            storage: Arc::clone(&self.storage),
            clock: Arc::clone(&self.clock),
            direction: sync_ctx.direction,
            saw_hello: false,
            completed_hash_phase: false,
            pending_requests: HashSet::new(),
            pages_transferred: 0,
            bytes_transferred: 0,
            pending_outgoing: VecDeque::new(),
            finished: false,
            requests,
        };
        let stream = futures::stream::unfold(state, step);
        Ok((Box::pin(stream), ctx))
    }
}

/// One iteration of the FSM. Drains `pending_outgoing` first; if empty,
/// pulls the next client envelope and routes it. Returns `None` to end
/// the response stream when the client hangs up after `Complete` and
/// no requests are outstanding.
async fn step<S: SyncStorage + Send + Sync + 'static>(
    mut state: FsmState<S>,
) -> Option<(Result<ServerEnvelope, ConnectError>, FsmState<S>)> {
    loop {
        if let Some(envelope) = state.pending_outgoing.pop_front() {
            return Some((Ok(envelope), state));
        }
        if state.finished {
            return None;
        }
        match state.requests.next().await {
            Some(Ok(envelope)) => {
                if let Err(e) = process_envelope(&mut state, &envelope) {
                    state.pending_outgoing.push_back(error_envelope(&e));
                    state.finished = true;
                }
            }
            Some(Err(e)) => {
                return Some((Err(e), {
                    state.finished = true;
                    state
                }));
            }
            None => {
                // Client closed without `Complete`. If there's an
                // unsent SyncComplete to emit, queue it; otherwise end.
                if state.saw_hello && state.pending_requests.is_empty() {
                    state.pending_outgoing.push_back(sync_complete(&state));
                }
                state.finished = true;
            }
        }
    }
}

/// Route a single ClientEnvelope. Pure on the FSM state (no .await),
/// so the test path and the wasm path are byte-for-byte identical.
fn process_envelope<S: SyncStorage + Send + Sync + 'static>(
    state: &mut FsmState<S>,
    envelope: &OwnedView<ClientEnvelopeView<'static>>,
) -> Result<(), String> {
    let Some(payload) = &envelope.payload else {
        return Err("empty client envelope".into());
    };
    if !state.saw_hello {
        match payload {
            PayloadView::Hello(hello) => return handle_hello(state, hello),
            _ => return Err("first envelope must be Hello".into()),
        }
    }
    match payload {
        PayloadView::Hello(_) => Err("Hello may only be sent once".into()),
        PayloadView::PageHash(ph) => handle_page_hash(state, ph.page_no, ph.hash),
        PayloadView::PageHashBatch(b) => handle_page_hash_batch(state, b),
        PayloadView::PageData(pd) => handle_page_data(state, pd.page_no, pd.data),
        PayloadView::PageDataBatch(b) => handle_page_data_batch(state, b),
        PayloadView::Complete(_) => handle_complete(state),
    }
}

fn handle_hello<S: SyncStorage + Send + Sync + 'static>(
    state: &mut FsmState<S>,
    hello: &edgereplica_protocol::sync::v1::HelloView<'_>,
) -> Result<(), String> {
    if hello.protocol_version != PROTOCOL_VERSION {
        return Err(format!(
            "protocol_version mismatch: server={PROTOCOL_VERSION}, client={}",
            hello.protocol_version
        ));
    }
    state.saw_hello = true;

    let stored_max = state.storage.max_page().map_err(|e| e.to_string())?;
    state
        .pending_outgoing
        .push_back(envelope(ServerPayload::HelloReply(Box::new(HelloReply {
            protocol_version: PROTOCOL_VERSION,
            page_size: hello.page_size,
            max_page: stored_max,
            ..Default::default()
        }))));
    Ok(())
}

fn handle_page_hash<S: SyncStorage + Send + Sync + 'static>(
    state: &mut FsmState<S>,
    page_no: u32,
    hash: &str,
) -> Result<(), String> {
    let stored = state
        .storage
        .get_page_hash(page_no)
        .map_err(|e| e.to_string())?;
    if stored.as_deref() == Some(hash) {
        return Ok(());
    }
    match state.direction {
        Direction::Push => {
            // Track the request so SyncComplete waits for the matching PageData.
            state.pending_requests.insert(page_no);
            state
                .pending_outgoing
                .push_back(envelope(ServerPayload::RequestPage(Box::new(
                    RequestPage {
                        page_no,
                        ..Default::default()
                    },
                ))));
        }
        Direction::Pull => {
            // Pull: client reports its hash; server pushes canonical bytes
            // when it has them, otherwise stays silent (client's copy stands).
            if let Some(data) = state.storage.get_page(page_no).map_err(|e| e.to_string())? {
                state.bytes_transferred += data.len() as u64;
                state.pages_transferred += 1;
                state
                    .pending_outgoing
                    .push_back(envelope(ServerPayload::PageData(Box::new(PageData {
                        page_no,
                        data,
                        ..Default::default()
                    }))));
            }
        }
    }
    Ok(())
}

fn handle_page_hash_batch<S: SyncStorage + Send + Sync + 'static>(
    state: &mut FsmState<S>,
    batch: &PageHashBatchView<'_>,
) -> Result<(), String> {
    let stored = combined_hash(state.storage.as_ref(), batch.start_page, batch.end_page)
        .map_err(|e| e.to_string())?;
    if stored == batch.combined_hash {
        return Ok(());
    }
    let page_numbers: Vec<u32> = (batch.start_page..=batch.end_page).collect();
    state
        .pending_outgoing
        .push_back(envelope(ServerPayload::HashMismatchBatch(Box::new(
            HashMismatchBatch {
                page_numbers,
                ..Default::default()
            },
        ))));
    Ok(())
}

fn handle_page_data<S: SyncStorage + Send + Sync + 'static>(
    state: &mut FsmState<S>,
    page_no: u32,
    data: &[u8],
) -> Result<(), String> {
    state.pending_requests.remove(&page_no);
    let hash = page_hash(data);
    let now = state.clock.now_ms();
    state
        .storage
        .put_page(page_no, data, &hash, now)
        .map_err(|e| e.to_string())?;
    state.pages_transferred += 1;
    state.bytes_transferred += data.len() as u64;
    if state.completed_hash_phase && state.pending_requests.is_empty() {
        state.pending_outgoing.push_back(sync_complete(state));
    }
    Ok(())
}

fn handle_page_data_batch<S: SyncStorage + Send + Sync + 'static>(
    state: &mut FsmState<S>,
    batch: &PageDataBatchView<'_>,
) -> Result<(), String> {
    for page in batch.pages.iter() {
        handle_page_data(state, page.page_no, page.data)?;
    }
    Ok(())
}

fn handle_complete<S: SyncStorage + Send + Sync + 'static>(
    state: &mut FsmState<S>,
) -> Result<(), String> {
    state.completed_hash_phase = true;
    if state.pending_requests.is_empty() {
        state.pending_outgoing.push_back(sync_complete(state));
        state.finished = true;
    }
    Ok(())
}

fn envelope(payload: ServerPayload) -> ServerEnvelope {
    ServerEnvelope {
        payload: Some(payload),
        ..Default::default()
    }
}

fn sync_complete<S: SyncStorage + Send + Sync + 'static>(state: &FsmState<S>) -> ServerEnvelope {
    envelope(ServerPayload::SyncComplete(Box::new(SyncComplete {
        pages_transferred: state.pages_transferred,
        bytes_transferred: state.bytes_transferred,
        ..Default::default()
    })))
}

fn error_envelope(message: &str) -> ServerEnvelope {
    envelope(ServerPayload::Error(Box::new(SyncError {
        message: message.into(),
        ..Default::default()
    })))
}

// =================== Tests ===================

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use buffa::view::OwnedView;
    use connectrpc::Context as RpcContext;
    use edgereplica_protocol::sync::v1::{
        ClientEnvelope, Hello, PageData, PageHash, ServerEnvelope, SyncService,
        client_envelope::Payload as ClientPayload, server_envelope::Payload as ServerPayload,
    };
    use edgereplica_shared::{
        DatabaseId, Direction, OrgId, SharedClock, SyncContext, UserId, clock::FixedClock,
    };
    use futures::StreamExt as _;

    use crate::services::sync_storage::{InMemorySyncStorage, SyncStorage, page_hash};

    use super::{PROTOCOL_VERSION, SyncServer};

    fn ctx_for(direction: Direction) -> RpcContext {
        let mut ctx = RpcContext::default();
        ctx.extensions.insert(SyncContext {
            user: UserId::from("u_1"),
            org: OrgId::from("o_1"),
            database: DatabaseId::from("db_1"),
            direction,
            exp_unix: 9_999_999_999,
        });
        ctx
    }

    fn server(storage: Arc<InMemorySyncStorage>) -> SyncServer<InMemorySyncStorage> {
        let clock: SharedClock = FixedClock::new(1_700_000_000_000);
        SyncServer::new(storage, clock)
    }

    fn owned(envelope: ClientEnvelope) -> OwnedView<super::ClientEnvelopeView<'static>> {
        OwnedView::from_owned(&envelope).expect("encode envelope")
    }

    /// Drive the FSM with a fixed input vector and collect responses.
    async fn run(
        direction: Direction,
        storage: Arc<InMemorySyncStorage>,
        inputs: Vec<ClientEnvelope>,
    ) -> Vec<ServerEnvelope> {
        let req_stream = futures::stream::iter(inputs.into_iter().map(|e| Ok(owned(e))));
        let (resp, _ctx) = server(storage)
            .sync(ctx_for(direction), Box::pin(req_stream))
            .await
            .expect("sync");
        resp.map(|r| r.expect("response item"))
            .collect::<Vec<_>>()
            .await
    }

    fn hello() -> ClientEnvelope {
        ClientEnvelope {
            payload: Some(ClientPayload::Hello(Box::new(Hello {
                protocol_version: PROTOCOL_VERSION,
                page_size: 4096,
                max_page: 0,
                ..Default::default()
            }))),
            ..Default::default()
        }
    }

    fn page_hash_msg(page_no: u32, hash: &str) -> ClientEnvelope {
        ClientEnvelope {
            payload: Some(ClientPayload::PageHash(Box::new(PageHash {
                page_no,
                hash: hash.into(),
                ..Default::default()
            }))),
            ..Default::default()
        }
    }

    fn page_data_msg(page_no: u32, data: Vec<u8>) -> ClientEnvelope {
        ClientEnvelope {
            payload: Some(ClientPayload::PageData(Box::new(PageData {
                page_no,
                data,
                ..Default::default()
            }))),
            ..Default::default()
        }
    }

    fn complete() -> ClientEnvelope {
        ClientEnvelope {
            payload: Some(ClientPayload::Complete(Box::default())),
            ..Default::default()
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn empty_push_yields_hello_reply_and_sync_complete() {
        let storage = Arc::new(InMemorySyncStorage::new());
        let out = run(
            Direction::Push,
            Arc::clone(&storage),
            vec![hello(), complete()],
        )
        .await;
        assert_eq!(out.len(), 2);
        assert!(matches!(out[0].payload, Some(ServerPayload::HelloReply(_))));
        let ServerPayload::SyncComplete(sc) = out[1].payload.as_ref().unwrap() else {
            panic!("expected SyncComplete, got {:?}", out[1].payload);
        };
        assert_eq!(sc.pages_transferred, 0);
        assert_eq!(sc.bytes_transferred, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn push_unknown_page_triggers_request_then_stores_data() {
        let storage = Arc::new(InMemorySyncStorage::new());
        let data = vec![0xAB; 4096];
        let h = page_hash(&data);
        let out = run(
            Direction::Push,
            Arc::clone(&storage),
            vec![
                hello(),
                page_hash_msg(1, &h),
                page_data_msg(1, data.clone()),
                complete(),
            ],
        )
        .await;
        // Expected: HelloReply, RequestPage(1), SyncComplete(1, 4096).
        assert_eq!(out.len(), 3);
        assert!(matches!(out[0].payload, Some(ServerPayload::HelloReply(_))));
        match out[1].payload.as_ref().unwrap() {
            ServerPayload::RequestPage(rp) => assert_eq!(rp.page_no, 1),
            other => panic!("expected RequestPage, got {other:?}"),
        }
        match out[2].payload.as_ref().unwrap() {
            ServerPayload::SyncComplete(sc) => {
                assert_eq!(sc.pages_transferred, 1);
                assert_eq!(sc.bytes_transferred, 4096);
            }
            other => panic!("expected SyncComplete, got {other:?}"),
        }
        assert_eq!(storage.get_page(1).unwrap(), Some(data));
        assert_eq!(storage.get_page_hash(1).unwrap(), Some(h));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn push_matching_hash_skips_request() {
        let storage = Arc::new(InMemorySyncStorage::new());
        let data = vec![0xCD; 4096];
        let h = page_hash(&data);
        storage.put_page(1, &data, &h, 0).unwrap();

        let out = run(
            Direction::Push,
            Arc::clone(&storage),
            vec![hello(), page_hash_msg(1, &h), complete()],
        )
        .await;
        // HelloReply then SyncComplete(0, 0) — no RequestPage was sent.
        assert_eq!(out.len(), 2);
        assert!(matches!(out[0].payload, Some(ServerPayload::HelloReply(_))));
        match out[1].payload.as_ref().unwrap() {
            ServerPayload::SyncComplete(sc) => {
                assert_eq!(sc.pages_transferred, 0);
                assert_eq!(sc.bytes_transferred, 0);
            }
            other => panic!("expected SyncComplete, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pull_mismatch_streams_page_data() {
        let storage = Arc::new(InMemorySyncStorage::new());
        // DO has page 1 with bytes "old" — client claims hash for "new"
        // (i.e. its local copy differs). Server pushes the canonical bytes.
        storage.put_page(1, b"old", &page_hash(b"old"), 0).unwrap();
        let out = run(
            Direction::Pull,
            Arc::clone(&storage),
            vec![hello(), page_hash_msg(1, &page_hash(b"new")), complete()],
        )
        .await;
        assert_eq!(out.len(), 3);
        assert!(matches!(out[0].payload, Some(ServerPayload::HelloReply(_))));
        match out[1].payload.as_ref().unwrap() {
            ServerPayload::PageData(pd) => {
                assert_eq!(pd.page_no, 1);
                assert_eq!(pd.data, b"old");
            }
            other => panic!("expected PageData, got {other:?}"),
        }
        match out[2].payload.as_ref().unwrap() {
            ServerPayload::SyncComplete(sc) => {
                assert_eq!(sc.pages_transferred, 1);
                assert_eq!(sc.bytes_transferred, 3);
            }
            other => panic!("expected SyncComplete, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pull_matching_hash_emits_nothing_extra() {
        let storage = Arc::new(InMemorySyncStorage::new());
        let data = vec![0xEE; 4096];
        let h = page_hash(&data);
        storage.put_page(1, &data, &h, 0).unwrap();
        let out = run(
            Direction::Pull,
            Arc::clone(&storage),
            vec![hello(), page_hash_msg(1, &h), complete()],
        )
        .await;
        assert_eq!(out.len(), 2);
        assert!(matches!(out[0].payload, Some(ServerPayload::HelloReply(_))));
        match out[1].payload.as_ref().unwrap() {
            ServerPayload::SyncComplete(sc) => {
                assert_eq!(sc.pages_transferred, 0);
                assert_eq!(sc.bytes_transferred, 0);
            }
            other => panic!("expected SyncComplete, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn first_envelope_must_be_hello() {
        let storage = Arc::new(InMemorySyncStorage::new());
        let out = run(
            Direction::Push,
            Arc::clone(&storage),
            vec![page_hash_msg(1, "deadbeef")],
        )
        .await;
        assert_eq!(out.len(), 1);
        match out[0].payload.as_ref().unwrap() {
            ServerPayload::Error(e) => assert!(e.message.contains("Hello")),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unauthenticated_when_no_sync_context() {
        let storage = Arc::new(InMemorySyncStorage::new());
        let req_stream = futures::stream::iter(Vec::<
            Result<OwnedView<super::ClientEnvelopeView<'static>>, _>,
        >::new());
        let result = server(storage)
            .sync(RpcContext::default(), Box::pin(req_stream))
            .await;
        assert!(result.is_err(), "missing sync context should reject");
    }
}
