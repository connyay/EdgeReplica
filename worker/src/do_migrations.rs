//! Versioned schema migrations for the EdgeReplica DurableObject's
//! `SqlStorage`. v1 EdgeReplica hardcoded `CREATE TABLE IF NOT EXISTS`
//! calls in `DurableObject::new`; that's a constructor, not a migration
//! entry point, and it leaves no room for future ALTERs.
//!
//! Each migration is a single `(version, sql)` pair. `sql` may contain
//! multiple statements separated by `;`. On first request per isolate the
//! DO calls `ensure_schema(&sql)` which reads `MAX(version)` from
//! `schema_version`, applies any newer migrations in order, then stamps
//! the new version.

#![cfg(target_arch = "wasm32")]

use worker::SqlStorage;

pub struct Migration {
    pub version: i64,
    pub sql: &'static str,
}

pub const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    sql: r#"
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at_ms INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS pages (
            page_no INTEGER PRIMARY KEY,
            data BLOB NOT NULL,
            hash TEXT NOT NULL,
            updated_at_ms INTEGER NOT NULL
        );
    "#,
}];

#[derive(Debug)]
pub struct MigrationError(pub String);

impl std::fmt::Display for MigrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for MigrationError {}

pub fn ensure_schema(sql: &SqlStorage, now_ms: i64) -> Result<(), MigrationError> {
    // The first migration creates `schema_version`; until that runs the
    // SELECT below fails. Wrap in a fallible read that treats "table
    // missing" as version 0.
    let current = current_version(sql).unwrap_or(0);
    for m in MIGRATIONS.iter().filter(|m| m.version > current) {
        for statement in split_statements(m.sql) {
            sql.exec(&statement, None)
                .map_err(|e| MigrationError(format!("v{}: {e} [{statement}]", m.version)))?;
        }
        // Use simple parameter binding rather than format! to keep the SQL
        // shape literal across migrations.
        sql.exec(
            "INSERT OR REPLACE INTO schema_version (version, applied_at_ms) VALUES (?, ?)",
            Some(vec![m.version.into(), now_ms.into()]),
        )
        .map_err(|e| MigrationError(format!("v{} stamp: {e}", m.version)))?;
    }
    Ok(())
}

fn current_version(sql: &SqlStorage) -> Result<i64, MigrationError> {
    let cursor = sql
        .exec("SELECT MAX(version) AS v FROM schema_version", None)
        .map_err(|e| MigrationError(format!("read version: {e}")))?;
    #[derive(serde::Deserialize)]
    struct Row {
        v: Option<i64>,
    }
    let mut iter = cursor.next::<Row>();
    match iter.next() {
        Some(Ok(row)) => Ok(row.v.unwrap_or(0)),
        Some(Err(e)) => Err(MigrationError(format!("decode version: {e}"))),
        None => Ok(0),
    }
}

/// Split a multi-statement SQL string on `;`, stripping whole-line `--`
/// comments and collapsing whitespace. `SqlStorage::exec` runs one
/// statement per call, so we don't get to lean on `D1Database::exec`'s
/// line-oriented heuristic here.
///
/// Naive: does not handle `;` inside string literals or `BEGIN ... END`
/// blocks. Adequate for the current `CREATE TABLE` corpus; revisit
/// before adding triggers or seed `INSERT`s with embedded semicolons.
fn split_statements(sql: &str) -> Vec<String> {
    let mut out = Vec::new();
    for stmt in sql.split(';') {
        let cleaned: String = stmt
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with("--"))
            .collect::<Vec<_>>()
            .join(" ");
        let cleaned = cleaned.trim().to_string();
        if !cleaned.is_empty() {
            out.push(cleaned);
        }
    }
    out
}
