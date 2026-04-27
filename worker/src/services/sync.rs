//! `edgereplica.sync.v1.SyncService` implementation. Hosted **inside** the
//! EdgeReplica DurableObject so the FSM lives next to the SqlStorage it
//! reads / writes.
//!
//! Currently a stub: read the first envelope, echo a `HelloReply`, close.
//! The full `futures::stream::unfold` FSM (paging through `SqlStorage`)
//! lands later.

use std::pin::Pin;

use buffa::view::OwnedView;
use connectrpc::{ConnectError, Context as RpcContext};
use edgereplica_protocol::sync::v1::{
    ClientEnvelopeView, HelloReply, ServerEnvelope, SyncService, client_envelope::PayloadView,
    server_envelope::Payload as ServerPayload,
};
use futures::{Stream, StreamExt as _};

pub struct SyncServer;

impl SyncServer {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SyncServer {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncService for SyncServer {
    async fn sync(
        &self,
        ctx: RpcContext,
        mut requests: Pin<
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
        let next = requests.next().await;
        let (proto_version, page_size) = if let Some(Ok(envelope)) = &next
            && let Some(PayloadView::Hello(hello)) = &envelope.payload
        {
            (hello.protocol_version, hello.page_size)
        } else {
            (0, 0)
        };

        let reply = ServerEnvelope {
            payload: Some(ServerPayload::HelloReply(Box::new(HelloReply {
                protocol_version: proto_version,
                page_size,
                max_page: 0,
                ..Default::default()
            }))),
            ..Default::default()
        };
        let stream = futures::stream::iter(vec![Ok(reply)]);
        Ok((Box::pin(stream), ctx))
    }
}
