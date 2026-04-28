//! Read raw SQLite pages via the `sqlite_dbpage` virtual table, hash
//! them, and yield them in chunks.

use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};
use sha2::{Digest, Sha256};

pub struct Page {
    pub page_no: u32,
    pub data: Vec<u8>,
    pub hash: String,
}

pub fn iter_chunks(path: &Path, chunk_size: usize) -> Result<ChunkIter> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("open {}", path.display()))?;
    Ok(ChunkIter::new(conn, chunk_size))
}

pub struct ChunkIter {
    conn: Connection,
    chunk_size: usize,
    next_page: u32,
    max_page: u32,
}

impl ChunkIter {
    fn new(conn: Connection, chunk_size: usize) -> Self {
        // Empty / brand-new DBs return NULL from MAX(pgno); IFNULL → 0.
        let max_page: u32 = conn
            .query_row(
                "SELECT IFNULL(MAX(pgno), 0) FROM sqlite_dbpage('main')",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
            .max(0) as u32;
        Self {
            conn,
            chunk_size: chunk_size.max(1),
            next_page: 1,
            max_page,
        }
    }

    pub fn max_page(&self) -> u32 {
        self.max_page
    }
}

impl Iterator for ChunkIter {
    type Item = Result<Vec<Page>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_page > self.max_page {
            return None;
        }
        let start = self.next_page;
        let end = (start + self.chunk_size as u32 - 1).min(self.max_page);
        self.next_page = end + 1;

        let mut stmt = match self.conn.prepare_cached(
            "SELECT pgno, data FROM sqlite_dbpage('main') \
             WHERE pgno BETWEEN ?1 AND ?2 ORDER BY pgno",
        ) {
            Ok(s) => s,
            Err(e) => return Some(Err(e.into())),
        };
        let rows = stmt.query_map([start as i64, end as i64], |row| {
            let pgno: i64 = row.get(0)?;
            let data: Vec<u8> = row.get(1)?;
            Ok((pgno as u32, data))
        });
        let rows = match rows {
            Ok(r) => r,
            Err(e) => return Some(Err(e.into())),
        };

        let mut out = Vec::with_capacity(self.chunk_size);
        for r in rows {
            match r {
                Ok((page_no, data)) => {
                    let hash = page_hash_hex(&data);
                    out.push(Page {
                        page_no,
                        data,
                        hash,
                    });
                }
                Err(e) => return Some(Err(e.into())),
            }
        }
        Some(Ok(out))
    }
}

pub fn page_hash_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn write_pages(path: &Path, pages: &[Page]) -> Result<()> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    )
    .with_context(|| format!("open rw {}", path.display()))?;
    let tx = conn.unchecked_transaction()?;
    {
        let mut stmt =
            tx.prepare("INSERT OR REPLACE INTO sqlite_dbpage(pgno, data) VALUES (?, ?)")?;
        for page in pages {
            stmt.execute((page.page_no as i64, &page.data))
                .with_context(|| format!("write page {}", page.page_no))?;
        }
    }
    tx.commit().context("commit page batch")
}
