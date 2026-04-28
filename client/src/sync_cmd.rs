//! `sync push` / `sync pull` — drives the bidi `SyncService.Sync` stream.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use edgereplica_protocol::sync::v1::{
    ClientEnvelope, Hello, PageData, PageHash, ServerEnvelope, ServerEnvelopeView,
    client_envelope::Payload as ClientPayload, server_envelope::Payload as ServerPayload,
};

use crate::config::{Config, resolve_secret};
use crate::pages::{PageReader, PageWriter};
use crate::transport;

/// Wire protocol version. Bumped together with the worker.
const PROTOCOL_VERSION: u32 = 1;
/// Number of `PageHash` envelopes to send before pausing to drain any
/// `RequestPage` responses queued by the server.
const HASH_BATCH: u32 = 64;
const DEFAULT_PAGE_SIZE: u32 = 4096;

type SyncStream<B> = connectrpc::client::BidiStream<B, ClientEnvelope, ServerEnvelopeView<'static>>;

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
    let (client, opts) = transport::authed_sync_client(&config, &token)?;
    let mut stream = client.sync_with_options(opts).await.context("open sync")?;

    let mut reader =
        PageReader::open(&args.db).with_context(|| format!("read {}", args.db.display()))?;
    let max_page = reader.max_page();

    stream
        .send(client_hello(max_page, DEFAULT_PAGE_SIZE))
        .await
        .context("send Hello")?;

    let hello_reply = expect_message(&mut stream).await?;
    match hello_reply.payload {
        Some(ServerPayload::HelloReply(_)) => {}
        Some(other) => bail!("expected HelloReply, got {other:?}"),
        None => bail!("server closed before HelloReply"),
    }

    let mut sent = 0u32;
    while let Some((pgno, hash)) = reader.next_hash()? {
        stream
            .send(client_page_hash(pgno, &hash))
            .await
            .with_context(|| format!("send PageHash {pgno}"))?;
        sent += 1;
        if sent.is_multiple_of(HASH_BATCH) {
            process_responses(&mut stream, &mut reader, false).await?;
        }
    }

    stream
        .send(client_complete())
        .await
        .context("send Complete")?;
    stream.close_send();
    process_responses(&mut stream, &mut reader, true).await?;

    Ok(())
}

pub async fn pull(args: PullArgs, config: Config) -> Result<()> {
    let token = resolve_secret(args.token, "EDGEREPLICA_SYNC_TOKEN", "token")?;
    let (client, opts) = transport::authed_sync_client(&config, &token)?;
    let mut stream = client.sync_with_options(opts).await.context("open sync")?;

    let (local_max, local_hashes) = if args.db.exists() {
        let mut reader = PageReader::open(&args.db)?;
        let max = reader.max_page();
        let mut hashes: HashMap<u32, String> = HashMap::with_capacity(max as usize);
        while let Some((pgno, hash)) = reader.next_hash()? {
            hashes.insert(pgno, hash);
        }
        (max, hashes)
    } else {
        (0, HashMap::new())
    };

    stream
        .send(client_hello(local_max, DEFAULT_PAGE_SIZE))
        .await
        .context("send Hello")?;

    let hello_reply = expect_message(&mut stream).await?;
    let server_max = match hello_reply.payload {
        Some(ServerPayload::HelloReply(reply)) => reply.max_page,
        Some(other) => bail!("expected HelloReply, got {other:?}"),
        None => bail!("server closed before HelloReply"),
    };

    let highest = local_max.max(server_max);
    let mut writer =
        PageWriter::open(&args.db).with_context(|| format!("open rw {}", args.db.display()))?;

    for page_no in 1..=highest {
        let local_hash = local_hashes.get(&page_no).map(String::as_str).unwrap_or("");
        stream
            .send(client_page_hash(page_no, local_hash))
            .await
            .with_context(|| format!("send PageHash {page_no}"))?;
        receive_pages(&mut stream, &mut writer, false).await?;
    }

    stream
        .send(client_complete())
        .await
        .context("send Complete")?;
    stream.close_send();
    receive_pages(&mut stream, &mut writer, true).await?;
    writer.commit()?;
    Ok(())
}

/// Read envelopes from the server; reply to `RequestPage` with bytes
/// the reader fetches on demand. Returns after one envelope when
/// `until_complete` is false, or after `SyncComplete`/`Error` when true.
async fn process_responses<B>(
    stream: &mut SyncStream<B>,
    reader: &mut PageReader,
    until_complete: bool,
) -> Result<()>
where
    B: http_body::Body<Data = bytes::Bytes> + Send + Unpin,
    B::Error: std::fmt::Display,
{
    loop {
        let Some(envelope) = stream.message().await.context("recv next")? else {
            return Ok(());
        };
        let envelope = envelope.to_owned_message();
        match envelope.payload {
            Some(ServerPayload::RequestPage(rp)) => {
                let data = reader.read_page(rp.page_no)?;
                stream
                    .send(client_page_data(rp.page_no, data))
                    .await
                    .with_context(|| format!("send PageData {}", rp.page_no))?;
            }
            Some(ServerPayload::RequestPages(rps)) => {
                for n in rps.page_numbers {
                    let data = reader.read_page(n)?;
                    stream
                        .send(client_page_data(n, data))
                        .await
                        .with_context(|| format!("send PageData {n}"))?;
                }
            }
            Some(ServerPayload::SyncComplete(sc)) => {
                println!(
                    "sync complete: {} pages, {} bytes",
                    sc.pages_transferred, sc.bytes_transferred
                );
                return Ok(());
            }
            Some(ServerPayload::Error(e)) => bail!("server error: {}", e.message),
            _ => {}
        }
        if !until_complete {
            return Ok(());
        }
    }
}

async fn receive_pages<B>(
    stream: &mut SyncStream<B>,
    writer: &mut PageWriter,
    until_complete: bool,
) -> Result<()>
where
    B: http_body::Body<Data = bytes::Bytes> + Send + Unpin,
    B::Error: std::fmt::Display,
{
    loop {
        let Some(envelope) = stream.message().await.context("recv next")? else {
            return Ok(());
        };
        let envelope = envelope.to_owned_message();
        match envelope.payload {
            Some(ServerPayload::PageData(pd)) => {
                writer.write(pd.page_no, &pd.data)?;
            }
            Some(ServerPayload::SyncComplete(sc)) => {
                println!(
                    "sync complete: {} pages, {} bytes",
                    sc.pages_transferred, sc.bytes_transferred
                );
                return Ok(());
            }
            Some(ServerPayload::Error(e)) => bail!("server error: {}", e.message),
            _ => {}
        }
        if !until_complete {
            return Ok(());
        }
    }
}

async fn expect_message<B>(stream: &mut SyncStream<B>) -> Result<ServerEnvelope>
where
    B: http_body::Body<Data = bytes::Bytes> + Send + Unpin,
    B::Error: std::fmt::Display,
{
    let envelope = stream
        .message()
        .await
        .context("recv next")?
        .ok_or_else(|| anyhow!("server closed unexpectedly"))?;
    Ok(envelope.to_owned_message())
}

fn envelope(payload: ClientPayload) -> ClientEnvelope {
    ClientEnvelope {
        payload: Some(payload),
        ..Default::default()
    }
}

fn client_hello(max_page: u32, page_size: u32) -> ClientEnvelope {
    envelope(ClientPayload::Hello(Box::new(Hello {
        protocol_version: PROTOCOL_VERSION,
        page_size,
        max_page,
        ..Default::default()
    })))
}

fn client_page_hash(page_no: u32, hash: &str) -> ClientEnvelope {
    envelope(ClientPayload::PageHash(Box::new(PageHash {
        page_no,
        hash: hash.to_string(),
        ..Default::default()
    })))
}

fn client_page_data(page_no: u32, data: Vec<u8>) -> ClientEnvelope {
    envelope(ClientPayload::PageData(Box::new(PageData {
        page_no,
        data,
        ..Default::default()
    })))
}

fn client_complete() -> ClientEnvelope {
    envelope(ClientPayload::Complete(Box::default()))
}
