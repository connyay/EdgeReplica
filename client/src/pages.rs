//! Streaming SQLite page I/O via the `sqlite_dbpage` virtual table.
//!
//! `PageReader` walks pages 1..=max_page yielding hashes without buffering
//! the data, and serves on-demand reads for `RequestPage` replies.
//! `PageWriter` holds an open transaction and writes each received page
//! immediately, rolling back on drop if `commit` isn't called.

use std::path::Path;

use anyhow::{Context, Result};
use bytes::Bytes;
use edgereplica_shared::page_hash;
use rusqlite::{Connection, OpenFlags};

pub struct PageReader {
    conn: Connection,
    next_page: u32,
    max_page: u32,
}

impl PageReader {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("open {}", path.display()))?;
        // Empty / brand-new DBs return NULL from MAX(pgno); IFNULL → 0.
        let max_page: u32 = conn
            .query_row(
                "SELECT IFNULL(MAX(pgno), 0) FROM sqlite_dbpage('main')",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
            .max(0) as u32;
        Ok(Self {
            conn,
            next_page: 1,
            max_page,
        })
    }

    pub fn max_page(&self) -> u32 {
        self.max_page
    }

    /// Read the next page's bytes, hash them, drop the bytes, return the
    /// hash. Returns `Ok(None)` when exhausted.
    pub fn next_hash(&mut self) -> Result<Option<(u32, Bytes)>> {
        if self.next_page > self.max_page {
            return Ok(None);
        }
        let pgno = self.next_page;
        let data = self.read_page(pgno)?;
        self.next_page = pgno + 1;
        Ok(Some((pgno, page_hash(&data))))
    }

    pub fn read_page(&mut self, page_no: u32) -> Result<Vec<u8>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT data FROM sqlite_dbpage('main') WHERE pgno = ?1")?;
        let data: Vec<u8> = stmt
            .query_row([page_no as i64], |r| r.get(0))
            .with_context(|| format!("read page {page_no}"))?;
        Ok(data)
    }
}

pub struct PageWriter {
    conn: Connection,
    committed: bool,
}

impl PageWriter {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )
        .with_context(|| format!("open rw {}", path.display()))?;
        conn.execute_batch("BEGIN DEFERRED")
            .context("begin transaction")?;
        Ok(Self {
            conn,
            committed: false,
        })
    }

    pub fn write(&mut self, page_no: u32, data: &[u8]) -> Result<()> {
        let mut stmt = self
            .conn
            .prepare_cached("INSERT OR REPLACE INTO sqlite_dbpage(pgno, data) VALUES (?, ?)")?;
        stmt.execute((page_no as i64, data))
            .with_context(|| format!("write page {page_no}"))?;
        Ok(())
    }

    pub fn commit(mut self) -> Result<()> {
        self.conn
            .execute_batch("COMMIT")
            .context("commit page batch")?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for PageWriter {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.conn.execute_batch("ROLLBACK");
        }
    }
}
