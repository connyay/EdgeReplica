//! Storage abstraction for the `SyncService` FSM.
//!
//! The FSM is the same code on every target — it just walks pages and
//! reads/writes hashes. Pinning it to `worker::SqlStorage` (wasm32 only)
//! would make it impossible to unit-test on the host. So we define a
//! narrow trait covering the operations the FSM actually needs, with two
//! impls: `SqlSyncStorage` (wasm32, real DO) and `InMemorySyncStorage`
//! (host tests).

use edgereplica_shared::StoreResult;

/// Subset of `SqlStorage` that the FSM relies on. Kept deliberately
/// minimal so `InMemorySyncStorage` (used only by tests) is trivial.
pub trait SyncStorage {
    fn get_page_hash(&self, page_no: u32) -> StoreResult<Option<String>>;
    fn get_page(&self, page_no: u32) -> StoreResult<Option<Vec<u8>>>;
    fn put_page(&self, page_no: u32, data: &[u8], hash: &str, now_ms: i64) -> StoreResult<()>;
    fn max_page(&self) -> StoreResult<u32>;
}

/// SHA-256 of the page bytes, hex-lowercase. Uniform across both impls
/// so a host test that hashes a page produces the same string the wasm
/// build would.
pub fn page_hash(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

/// Combined hash over a contiguous range. Stable across impls so a
/// `PageHashBatch` from the client matches a server-side recomputation
/// regardless of host vs wasm. Pages outside the stored range
/// contribute nothing.
pub fn combined_hash<S: SyncStorage>(storage: &S, start: u32, end: u32) -> StoreResult<String> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for page_no in start..=end {
        if let Some(h) = storage.get_page_hash(page_no)? {
            hasher.update(h.as_bytes());
        }
    }
    Ok(hex::encode(hasher.finalize()))
}

// =================== InMemory impl (host tests) ===================

#[cfg(any(test, not(target_arch = "wasm32")))]
pub use in_memory::InMemorySyncStorage;

#[cfg(any(test, not(target_arch = "wasm32")))]
mod in_memory {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use super::{StoreResult, SyncStorage};

    struct Page {
        data: Vec<u8>,
        hash: String,
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
        fn get_page_hash(&self, page_no: u32) -> StoreResult<Option<String>> {
            Ok(self
                .pages
                .lock()
                .unwrap()
                .get(&page_no)
                .map(|p| p.hash.clone()))
        }

        fn get_page(&self, page_no: u32) -> StoreResult<Option<Vec<u8>>> {
            Ok(self
                .pages
                .lock()
                .unwrap()
                .get(&page_no)
                .map(|p| p.data.clone()))
        }

        fn put_page(&self, page_no: u32, data: &[u8], hash: &str, _now_ms: i64) -> StoreResult<()> {
            self.pages.lock().unwrap().insert(
                page_no,
                Page {
                    data: data.to_vec(),
                    hash: hash.to_string(),
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
    use edgereplica_shared::{StoreError, StoreResult};
    use serde::Deserialize;
    use worker::SqlStorage;

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

    #[derive(Deserialize)]
    struct HashRow {
        hash: String,
    }

    #[derive(Deserialize)]
    struct DataRow {
        data: Vec<u8>,
    }

    #[derive(Deserialize)]
    struct MaxRow {
        // `MAX(...)` over an empty table yields NULL.
        v: Option<i64>,
    }

    impl SyncStorage for SqlSyncStorage {
        fn get_page_hash(&self, page_no: u32) -> StoreResult<Option<String>> {
            let cursor = self
                .sql
                .exec(
                    "SELECT hash FROM pages WHERE page_no = ?",
                    Some(vec![(page_no as i64).into()]),
                )
                .map_err(|e| err("get_page_hash", e))?;
            let mut iter = cursor.next::<HashRow>();
            match iter.next() {
                Some(Ok(row)) => Ok(Some(row.hash)),
                Some(Err(e)) => Err(StoreError::backend(format!("decode hash: {e}"))),
                None => Ok(None),
            }
        }

        fn get_page(&self, page_no: u32) -> StoreResult<Option<Vec<u8>>> {
            let cursor = self
                .sql
                .exec(
                    "SELECT data FROM pages WHERE page_no = ?",
                    Some(vec![(page_no as i64).into()]),
                )
                .map_err(|e| err("get_page", e))?;
            let mut iter = cursor.next::<DataRow>();
            match iter.next() {
                Some(Ok(row)) => Ok(Some(row.data)),
                Some(Err(e)) => Err(StoreError::backend(format!("decode data: {e}"))),
                None => Ok(None),
            }
        }

        fn put_page(&self, page_no: u32, data: &[u8], hash: &str, now_ms: i64) -> StoreResult<()> {
            self.sql
                .exec(
                    "INSERT OR REPLACE INTO pages (page_no, data, hash, updated_at_ms) \
                     VALUES (?, ?, ?, ?)",
                    Some(vec![
                        (page_no as i64).into(),
                        data.to_vec().into(),
                        hash.into(),
                        now_ms.into(),
                    ]),
                )
                .map_err(|e| err("put_page", e))?;
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
