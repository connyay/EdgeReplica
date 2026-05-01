//! Storage abstraction for the `SyncService` FSM.
//!
//! The FSM is the same code on every target — it just walks pages and
//! reads/writes hashes. Pinning it to `worker::SqlStorage` (wasm32 only)
//! would make it impossible to unit-test on the host. So we define a
//! narrow trait covering the operations the FSM actually needs, with two
//! impls: `SqlSyncStorage` (wasm32, real DO) and `InMemorySyncStorage`
//! (host tests).
//!
//! Hashes are 32-byte BLAKE3 digests carried as `bytes::Bytes` to match
//! the on-the-wire `SyncMessage` shape; no per-comparison hex encode.

use bytes::Bytes;

use crate::error::StoreResult;
pub use edgereplica_protocol::sync::page_hash;

/// Subset of `SqlStorage` that the FSM relies on. Kept deliberately
/// minimal so `InMemorySyncStorage` (used only by tests) is trivial.
pub trait SyncStorage {
    fn get_page_hash(&self, page_no: u32) -> StoreResult<Option<Bytes>>;
    fn get_page(&self, page_no: u32) -> StoreResult<Option<Bytes>>;
    fn put_page(&self, page_no: u32, data: &[u8], hash: &[u8], now_ms: i64) -> StoreResult<()>;
    fn max_page(&self) -> StoreResult<u32>;

    /// Combined BLAKE3 digest over the page hashes in `start..=end`, in
    /// page_no order. Default impl issues one query per page; the SQL impl
    /// overrides with a single range scan so `PageHashBatch` doesn't fan
    /// out into N queries.
    fn combined_hash(&self, start: u32, end: u32) -> StoreResult<Bytes> {
        let mut hasher = blake3::Hasher::new();
        for page_no in start..=end {
            if let Some(h) = self.get_page_hash(page_no)? {
                hasher.update(&h);
            }
        }
        Ok(Bytes::copy_from_slice(hasher.finalize().as_bytes()))
    }

    /// Iterate page bytes in `start..=end` in ascending page_no order,
    /// invoking `emit` once per page that exists. Default impl issues one
    /// query per page; the SQL impl overrides with a single cursor so a
    /// huge DB doesn't materialize as N `Vec<u8>`s on the heap. The
    /// callback is invoked under the cursor — pages can be sent and
    /// dropped one at a time without buffering the whole walk.
    fn iter_pages_in_range(
        &self,
        start: u32,
        end: u32,
        emit: &mut dyn FnMut(u32, Bytes) -> StoreResult<()>,
    ) -> StoreResult<()> {
        for page_no in start..=end {
            if let Some(data) = self.get_page(page_no)? {
                emit(page_no, data)?;
            }
        }
        Ok(())
    }
}

// =================== InMemory impl (host tests) ===================

#[cfg(any(test, not(target_arch = "wasm32")))]
pub use in_memory::InMemorySyncStorage;

#[cfg(any(test, not(target_arch = "wasm32")))]
mod in_memory {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use bytes::Bytes;

    use super::{StoreResult, SyncStorage};

    struct Page {
        data: Bytes,
        hash: Bytes,
    }

    /// Host-side fake. Mirrors `SqlSyncStorage` semantics exactly so a
    /// test can swap one for the other without changing the FSM.
    #[derive(Default)]
    pub struct InMemorySyncStorage {
        pages: Mutex<BTreeMap<u32, Page>>,
    }

    impl InMemorySyncStorage {
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl SyncStorage for InMemorySyncStorage {
        fn get_page_hash(&self, page_no: u32) -> StoreResult<Option<Bytes>> {
            Ok(self
                .pages
                .lock()
                .unwrap()
                .get(&page_no)
                .map(|p| p.hash.clone()))
        }

        fn get_page(&self, page_no: u32) -> StoreResult<Option<Bytes>> {
            Ok(self
                .pages
                .lock()
                .unwrap()
                .get(&page_no)
                .map(|p| p.data.clone()))
        }

        fn put_page(
            &self,
            page_no: u32,
            data: &[u8],
            hash: &[u8],
            _now_ms: i64,
        ) -> StoreResult<()> {
            self.pages.lock().unwrap().insert(
                page_no,
                Page {
                    data: Bytes::copy_from_slice(data),
                    hash: Bytes::copy_from_slice(hash),
                },
            );
            Ok(())
        }

        fn max_page(&self) -> StoreResult<u32> {
            Ok(self
                .pages
                .lock()
                .unwrap()
                .keys()
                .next_back()
                .copied()
                .unwrap_or(0))
        }
    }
}

// =================== SqlStorage impl (wasm32 / DO) ===================

#[cfg(target_arch = "wasm32")]
pub use sql_storage::SqlSyncStorage;

#[cfg(target_arch = "wasm32")]
mod sql_storage {
    use bytes::Bytes;
    use serde::Deserialize;
    use worker::SqlStorage;

    use crate::error::{StoreError, StoreResult};

    use super::SyncStorage;

    /// Adapter from `worker::SqlStorage` (DO-side) to [`SyncStorage`].
    /// Holds a *clone* of the storage handle (which is just a JS handle
    /// under the hood) so we can move it freely into the FSM closure.
    pub struct SqlSyncStorage {
        sql: SqlStorage,
    }

    impl SqlSyncStorage {
        pub fn new(sql: SqlStorage) -> Self {
            Self { sql }
        }
    }

    fn err(label: &str, e: worker::Error) -> StoreError {
        StoreError::backend(format!("{label}: {e}"))
    }

    // `Bytes` (not `Vec<u8>`) for BLOB columns — see CLAUDE.md gotcha.
    #[derive(Deserialize)]
    struct HashRow {
        hash: Bytes,
    }

    #[derive(Deserialize)]
    struct DataRow {
        data: Bytes,
    }

    #[derive(Deserialize)]
    struct PageRow {
        page_no: i64,
        data: Bytes,
    }

    #[derive(Deserialize)]
    struct MaxRow {
        // `MAX(...)` over an empty table yields NULL.
        v: Option<i64>,
    }

    impl SqlSyncStorage {
        fn first_blob<R, F>(
            &self,
            label: &'static str,
            sql: &str,
            page_no: u32,
            pick: F,
        ) -> StoreResult<Option<Bytes>>
        where
            R: for<'de> Deserialize<'de>,
            F: FnOnce(R) -> Bytes,
        {
            let cursor = self
                .sql
                .exec(sql, Some(vec![(page_no as i64).into()]))
                .map_err(|e| err(label, e))?;
            let mut iter = cursor.next::<R>();
            match iter.next() {
                Some(Ok(row)) => Ok(Some(pick(row))),
                Some(Err(e)) => Err(StoreError::backend(format!("decode {label}: {e}"))),
                None => Ok(None),
            }
        }
    }

    impl SyncStorage for SqlSyncStorage {
        fn get_page_hash(&self, page_no: u32) -> StoreResult<Option<Bytes>> {
            self.first_blob::<HashRow, _>(
                "get_page_hash",
                "SELECT hash FROM pages WHERE page_no = ?",
                page_no,
                |r| r.hash,
            )
        }

        fn get_page(&self, page_no: u32) -> StoreResult<Option<Bytes>> {
            self.first_blob::<DataRow, _>(
                "get_page",
                "SELECT data FROM pages WHERE page_no = ?",
                page_no,
                |r| r.data,
            )
        }

        fn put_page(&self, page_no: u32, data: &[u8], hash: &[u8], now_ms: i64) -> StoreResult<()> {
            self.sql
                .exec(
                    "INSERT OR REPLACE INTO pages (page_no, data, hash, updated_at_ms) \
                     VALUES (?, ?, ?, ?)",
                    Some(vec![
                        (page_no as i64).into(),
                        data.to_vec().into(),
                        hash.to_vec().into(),
                        now_ms.into(),
                    ]),
                )
                .map_err(|e| err("put_page", e))?;
            Ok(())
        }

        /// Single range scan rather than the trait default's per-page query.
        /// Hashes are fixed 32-byte digests, so the full result set fits in
        /// `(end - start + 1) * 32` bytes — bounded enough to materialize.
        fn combined_hash(&self, start: u32, end: u32) -> StoreResult<Bytes> {
            let cursor = self
                .sql
                .exec(
                    "SELECT hash FROM pages WHERE page_no BETWEEN ? AND ? \
                     ORDER BY page_no",
                    Some(vec![(start as i64).into(), (end as i64).into()]),
                )
                .map_err(|e| err("combined_hash", e))?;
            let mut hasher = blake3::Hasher::new();
            for row in cursor.next::<HashRow>() {
                let row = row.map_err(|e| StoreError::backend(format!("decode hash: {e}")))?;
                hasher.update(&row.hash);
            }
            Ok(Bytes::copy_from_slice(hasher.finalize().as_bytes()))
        }

        /// Single cursor over the page range. The caller's `emit` runs under
        /// the cursor — each `Bytes` is dropped (and its frame shipped) before
        /// the next row is decoded, so a 1 GB DB doesn't materialize 1 GB of
        /// `Bytes` on the heap.
        fn iter_pages_in_range(
            &self,
            start: u32,
            end: u32,
            emit: &mut dyn FnMut(u32, Bytes) -> StoreResult<()>,
        ) -> StoreResult<()> {
            let cursor = self
                .sql
                .exec(
                    "SELECT page_no, data FROM pages WHERE page_no BETWEEN ? AND ? \
                     ORDER BY page_no",
                    Some(vec![(start as i64).into(), (end as i64).into()]),
                )
                .map_err(|e| err("iter_pages_in_range", e))?;
            for row in cursor.next::<PageRow>() {
                let row = row.map_err(|e| StoreError::backend(format!("decode page: {e}")))?;
                emit(row.page_no.max(0) as u32, row.data)?;
            }
            Ok(())
        }

        fn max_page(&self) -> StoreResult<u32> {
            let cursor = self
                .sql
                .exec("SELECT MAX(page_no) AS v FROM pages", None)
                .map_err(|e| err("max_page", e))?;
            let mut iter = cursor.next::<MaxRow>();
            match iter.next() {
                Some(Ok(row)) => Ok(row.v.unwrap_or(0).max(0) as u32),
                Some(Err(e)) => Err(StoreError::backend(format!("decode max: {e}"))),
                None => Ok(0),
            }
        }
    }
}
