//! WebSocket sync handler hosted inside the EdgeReplica DurableObject.
//!
//! The worker forwards a WebSocket upgrade after verifying the sync
//! macaroon at the public edge. This handler re-verifies on the inside
//! (defense in depth — the DO never implicitly trusts the worker), then
//! drives [`SyncFsm`] over a [`WebSocketPair`].
//!
//! The sync direction (push/pull) comes from the verified macaroon.

#![cfg(target_arch = "wasm32")]

use std::sync::Arc;

use edgereplica_shared::{
    Keyring, SharedClock, SyncMessage, decode_frame, encode_frame, verify_sync,
};
use futures::StreamExt as _;
use worker::{
    Headers, Request, Response, ResponseBuilder, Result, SqlStorage, WebSocket, WebSocketPair,
    WebsocketEvent, wasm_bindgen_futures, web_sys,
};

use crate::middleware::extract_bearer;
use crate::services::SyncFsm;
use crate::services::sync_storage::SqlSyncStorage;

/// Handle a WebSocket upgrade request inside the DO. Returns the 101
/// response with the client end of the pair attached, or a 4xx if auth
/// fails. The server end is driven by a `spawn_local` task that runs the
/// FSM until the client closes the connection or the FSM emits
/// `SyncComplete`.
pub fn handle_upgrade(
    sql: SqlStorage,
    clock: SharedClock,
    keyring: Arc<Keyring>,
    req: &Request,
) -> Result<Response> {
    let sync_ctx = match verify_token(req.headers(), keyring.as_ref(), &clock) {
        Ok(ctx) => ctx,
        Err(status) => return status_response(status, "invalid sync token"),
    };

    let pair = WebSocketPair::new()?;
    let server = pair.server;
    // Force binary frames to arrive as ArrayBuffer rather than Blob. workerd's
    // default is Blob, and worker-rs's `MessageEvent::bytes()` constructs the
    // Vec via `Uint8Array::new(&data)` — that path silently produces an empty
    // Vec for Blob inputs (you'd need `blob.array_buffer().await` to actually
    // read it). Without this, every binary frame looks empty on the server.
    let raw: &web_sys::WebSocket = server.as_ref();
    raw.set_binary_type(web_sys::BinaryType::Arraybuffer);
    server.accept()?;

    let storage = Arc::new(SqlSyncStorage::new(sql));
    let mut fsm = SyncFsm::new(storage, clock, sync_ctx.direction);

    let server_for_task = server.clone();
    wasm_bindgen_futures::spawn_local(async move {
        let mut events = match server_for_task.events() {
            Ok(s) => s,
            Err(e) => {
                worker::console_error!("ws events stream: {e}");
                return;
            }
        };

        while let Some(event) = events.next().await {
            match event {
                Ok(WebsocketEvent::Message(msg)) => {
                    let Some(bytes) = msg.bytes() else {
                        send_error(&server_for_task, "expected binary frame");
                        let _ = server_for_task
                            .close::<&str>(Some(1003), Some("text frames not supported"));
                        return;
                    };
                    let parsed = match decode_frame(&bytes) {
                        Ok(m) => m,
                        Err(e) => {
                            worker::console_error!(
                                "ws decode failed (bytes_len={}, first={:?}): {e}",
                                bytes.len(),
                                bytes.first()
                            );
                            send_error(&server_for_task, &format!("decode: {e}"));
                            let _ =
                                server_for_task.close::<&str>(Some(1002), Some("protocol error"));
                            return;
                        }
                    };
                    // Ship each FSM-emitted frame inline so a multi-GB pull
                    // walk doesn't buffer pages in worker RAM. A send
                    // failure aborts the apply call via the closure's Err.
                    let mut send_failed = false;
                    let result = fsm.apply(&parsed, &mut |outbound| {
                        if send_message(&server_for_task, &outbound) {
                            Ok(())
                        } else {
                            send_failed = true;
                            Err("ws send".into())
                        }
                    });
                    if send_failed {
                        return;
                    }
                    match result {
                        Ok(()) => {
                            if fsm.done() {
                                let _ = server_for_task
                                    .close::<&str>(Some(1000), Some("sync complete"));
                                return;
                            }
                        }
                        Err(e) => {
                            send_error(&server_for_task, &e);
                            let _ = server_for_task.close::<&str>(Some(1011), Some("server error"));
                            return;
                        }
                    }
                }
                Ok(WebsocketEvent::Close(_)) => {
                    fsm.client_closed();
                    return;
                }
                Err(e) => {
                    worker::console_error!("ws event error: {e}");
                    return;
                }
            }
        }
    });

    Ok(ResponseBuilder::new()
        .with_websocket(pair.client)
        .with_status(101)
        .empty())
}

fn verify_token(
    headers: &Headers,
    keyring: &Keyring,
    clock: &SharedClock,
) -> std::result::Result<edgereplica_shared::SyncContext, u16> {
    let raw = headers
        .get("Authorization")
        .map_err(|_| 400u16)?
        .ok_or(401u16)?;
    let token = extract_bearer(&raw).ok_or(401u16)?;
    verify_sync(keyring, clock.now_unix_seconds(), token).map_err(|_| 401u16)
}

fn status_response(status: u16, body: &str) -> Result<Response> {
    Response::error(body.to_string(), status)
}

fn send_message(socket: &WebSocket, msg: &SyncMessage) -> bool {
    let frame = match encode_frame(msg) {
        Ok(f) => f,
        Err(e) => {
            worker::console_error!("encode: {e}");
            return false;
        }
    };
    if let Err(e) = socket.send_with_bytes(frame) {
        worker::console_error!("send: {e}");
        return false;
    }
    true
}

fn send_error(socket: &WebSocket, message: &str) {
    let _ = send_message(
        socket,
        &SyncMessage::Error {
            message: message.to_string(),
        },
    );
}
