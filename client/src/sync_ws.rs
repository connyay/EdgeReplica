//! WebSocket sync client. Drives push and pull against the worker's
//! `/sync` endpoint. Frames are MessagePack-encoded `SyncMessage`s
//! prefixed with a one-byte protocol version (see
//! [`edgereplica_protocol::sync`]).
//!
//! Auth: the macaroon goes on the upgrade request as
//! `Authorization: Bearer <token>`. The worker rejects bad tokens with
//! 401 before the upgrade completes.

use std::collections::VecDeque;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use clap::Args;
use edgereplica_protocol::sync::{
    PROTOCOL_VERSION as SYNC_PROTOCOL_VERSION, SyncMessage, decode_frame, encode_frame,
};
use futures::{SinkExt, StreamExt};
use http::HeaderValue;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        Message,
        client::IntoClientRequest,
        handshake::client::{Request as ClientRequest, generate_key},
    },
};

use crate::config::{Config, resolve_secret};
use crate::pages::{PageReader, PageWriter};

/// Wire-protocol version carried in the `Hello` handshake. Same value as
/// the frame-byte [`SYNC_PROTOCOL_VERSION`], widened to the message field.
const HANDSHAKE_VERSION: u32 = SYNC_PROTOCOL_VERSION as u32;
const DEFAULT_PAGE_SIZE: u32 = 4096;

#[derive(Args, Debug)]
pub struct PushArgs {
    /// Local SQLite database to push.
    #[arg(long)]
    pub db: PathBuf,
    /// Sync token (output of `edgereplica db token --direction push`).
    /// Defaults to `EDGEREPLICA_SYNC_TOKEN`.
    #[arg(long)]
    pub token: Option<String>,
}

#[derive(Args, Debug)]
pub struct PullArgs {
    /// Local SQLite database to receive into. Created if missing.
    #[arg(long)]
    pub db: PathBuf,
    #[arg(long)]
    pub token: Option<String>,
}

pub async fn push(args: PushArgs, config: Config) -> Result<()> {
    let token = resolve_secret(args.token, "EDGEREPLICA_SYNC_TOKEN", "token")?;
    let mut ws = connect(&config.server, &token).await?;

    let mut reader =
        PageReader::open(&args.db).with_context(|| format!("read {}", args.db.display()))?;
    let max_page = reader.max_page();

    handshake(&mut ws, max_page).await?;

    // Stream every (page_no, hash) we have. The server queues a
    // RequestPage for each mismatch; we buffer those and serve them
    // after we've finished sending hashes.
    let mut pending: VecDeque<u32> = VecDeque::new();
    while let Some((page_no, hash)) = reader.next_hash()? {
        send(&mut ws, &SyncMessage::PageHash { page_no, hash }).await?;
        drain_ready(&mut ws, &mut pending).await?;
    }
    send(&mut ws, &SyncMessage::Complete).await?;

    loop {
        // Serve a queued request first if we have one.
        if let Some(page_no) = pending.pop_front() {
            let data = reader
                .read_page(page_no)
                .with_context(|| format!("read page {page_no}"))?;
            send(
                &mut ws,
                &SyncMessage::PageData {
                    page_no,
                    data: Bytes::from(data),
                },
            )
            .await?;
            continue;
        }

        match recv(&mut ws).await? {
            SyncMessage::RequestPage { page_no } => pending.push_back(page_no),
            SyncMessage::RequestPages { page_numbers } => pending.extend(page_numbers),
            SyncMessage::SyncComplete {
                pages_transferred,
                bytes_transferred,
            } => {
                println!("sync complete: {pages_transferred} pages, {bytes_transferred} bytes");
                let _ = ws.close(None).await;
                return Ok(());
            }
            SyncMessage::Error { message } => bail!("server error: {message}"),
            other => bail!("unexpected message during push drain: {other:?}"),
        }
    }
}

pub async fn pull(args: PullArgs, config: Config) -> Result<()> {
    let token = resolve_secret(args.token, "EDGEREPLICA_SYNC_TOKEN", "token")?;
    let mut ws = connect(&config.server, &token).await?;

    let local_max = if args.db.exists() {
        PageReader::open(&args.db)?.max_page()
    } else {
        0
    };

    handshake(&mut ws, local_max).await?;

    // Send a hash for every local page so the server can decide which
    // ones differ.
    if local_max > 0 {
        let mut reader = PageReader::open(&args.db)?;
        while let Some((page_no, hash)) = reader.next_hash()? {
            send(&mut ws, &SyncMessage::PageHash { page_no, hash }).await?;
        }
    }
    send(&mut ws, &SyncMessage::Complete).await?;

    let mut writer =
        PageWriter::open(&args.db).with_context(|| format!("open rw {}", args.db.display()))?;
    let mut pages_written = 0u64;
    loop {
        match recv(&mut ws).await? {
            SyncMessage::PageData { page_no, data } => {
                writer
                    .write(page_no, data.as_ref())
                    .with_context(|| format!("write page {page_no}"))?;
                pages_written += 1;
            }
            SyncMessage::PageDataBatch { pages } => {
                for entry in pages {
                    writer
                        .write(entry.page_no, entry.data.as_ref())
                        .with_context(|| format!("write page {}", entry.page_no))?;
                    pages_written += 1;
                }
            }
            SyncMessage::SyncComplete {
                pages_transferred,
                bytes_transferred,
            } => {
                println!(
                    "sync complete: {pages_transferred} pages, {bytes_transferred} bytes (wrote {pages_written} locally)"
                );
                writer.commit().context("commit page batch")?;
                let _ = ws.close(None).await;
                return Ok(());
            }
            SyncMessage::Error { message } => bail!("server error: {message}"),
            other => bail!("unexpected message during pull: {other:?}"),
        }
    }
}

// ====================== Connection / framing ======================

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect(server: &str, token: &str) -> Result<Ws> {
    let url = ws_url(server)?;
    let mut request: ClientRequest = url
        .as_str()
        .into_client_request()
        .with_context(|| format!("build ws request from {url}"))?;
    let headers = request.headers_mut();
    headers.insert(
        "Authorization",
        format!("Bearer {token}")
            .parse()
            .context("authorization header")?,
    );
    // tungstenite normally fills these in; do it explicitly so an
    // intermediary that strips defaulted headers can't break the
    // upgrade.
    headers.insert(
        "Sec-WebSocket-Key",
        generate_key().parse().context("ws key")?,
    );
    headers.insert("Sec-WebSocket-Version", HeaderValue::from_static("13"));
    headers.insert("Upgrade", HeaderValue::from_static("websocket"));
    headers.insert("Connection", HeaderValue::from_static("Upgrade"));

    let (ws, _resp) = connect_async(request).await.context("ws connect")?;
    Ok(ws)
}

fn ws_url(server: &str) -> Result<String> {
    let trimmed = server.trim_end_matches('/');
    let with_scheme = if let Some(rest) = trimmed.strip_prefix("http://") {
        format!("ws://{rest}")
    } else if let Some(rest) = trimmed.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if trimmed.starts_with("ws://") || trimmed.starts_with("wss://") {
        trimmed.to_string()
    } else {
        return Err(anyhow!(
            "unsupported server scheme in `{server}` (expected http/https/ws/wss)"
        ));
    };
    Ok(format!("{with_scheme}/sync"))
}

/// Send `Hello` and verify the server's `HelloReply` matches our protocol
/// version. Used by both push and pull, which only differ in `max_page`.
async fn handshake(ws: &mut Ws, max_page: u32) -> Result<()> {
    send(
        ws,
        &SyncMessage::Hello {
            protocol_version: HANDSHAKE_VERSION,
            page_size: DEFAULT_PAGE_SIZE,
            max_page,
        },
    )
    .await?;
    match recv(ws).await? {
        SyncMessage::HelloReply {
            protocol_version, ..
        } if protocol_version == HANDSHAKE_VERSION => Ok(()),
        SyncMessage::HelloReply {
            protocol_version, ..
        } => bail!(
            "protocol_version mismatch: client={HANDSHAKE_VERSION}, server={protocol_version}"
        ),
        SyncMessage::Error { message } => bail!("server error: {message}"),
        other => bail!("expected HelloReply, got {other:?}"),
    }
}

async fn send(ws: &mut Ws, msg: &SyncMessage) -> Result<()> {
    let frame = encode_frame(msg).context("encode frame")?;
    ws.send(Message::Binary(frame)).await.context("ws send")?;
    Ok(())
}

async fn recv(ws: &mut Ws) -> Result<SyncMessage> {
    loop {
        let next = ws
            .next()
            .await
            .ok_or_else(|| anyhow!("ws closed before SyncComplete"))?;
        match next.context("ws read")? {
            Message::Binary(bytes) => return decode_frame(&bytes).context("decode frame"),
            Message::Close(frame) => {
                bail!(
                    "server closed connection: {}",
                    frame
                        .map(|f| format!("{} {}", f.code, f.reason))
                        .unwrap_or_default()
                )
            }
            // Pings are handled by tokio-tungstenite automatically; pongs
            // and text frames are both protocol violations on our channel
            // but cheap to ignore.
            Message::Pong(_) | Message::Ping(_) | Message::Frame(_) => continue,
            Message::Text(t) => bail!("unexpected text frame: {t}"),
        }
    }
}

/// Drain any frames the WebSocket already has buffered without blocking.
/// We use this between `PageHash` sends so server `RequestPage` frames
/// land in the pending queue early — pages don't have to wait until
/// the hash phase ends.
async fn drain_ready(ws: &mut Ws, pending: &mut VecDeque<u32>) -> Result<()> {
    use std::task::Poll;

    futures::future::poll_fn(|cx| {
        loop {
            match ws.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(Message::Binary(bytes)))) => match decode_frame(&bytes) {
                    Ok(SyncMessage::RequestPage { page_no }) => pending.push_back(page_no),
                    Ok(SyncMessage::RequestPages { page_numbers }) => pending.extend(page_numbers),
                    Ok(SyncMessage::Error { message }) => {
                        return Poll::Ready(Err(anyhow!("server error: {message}")));
                    }
                    Ok(other) => {
                        return Poll::Ready(Err(anyhow!("unexpected mid-hash message: {other:?}")));
                    }
                    Err(e) => return Poll::Ready(Err(anyhow!("decode frame: {e}"))),
                },
                Poll::Ready(Some(Ok(_))) => continue,
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(anyhow!("ws read: {e}")));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(anyhow!("ws closed during hash phase")));
                }
                Poll::Pending => return Poll::Ready(Ok(())),
            }
        }
    })
    .await
}
