use crate::config::EncryptionAlgorithm;
use rusqlite::{params, Connection};
use std::path::PathBuf;

use super::db::{current_timestamp, delete_session_db, session_db_path, SCHEMA_VERSION};

const UPLOAD_PREFIX: &str = "upload";

/// Metadata for creating an upload session.
pub struct UploadMeta {
    pub file_path: PathBuf,
    pub file_hash: String,
    pub file_hash_full: String,
    pub file_size: u64,
    pub chunk_size: usize,
    pub total_chunks: usize,
    pub pubkey: String,
    pub encryption: EncryptionAlgorithm,
    pub relays: Vec<String>,
}

/// Upload session for tracking published chunks.
pub struct UploadSession {
    conn: Connection,
    db_path: PathBuf,
    pub total_chunks: usize,
}

impl UploadSession {
    /// Check if an upload session exists for the given file hash.
    pub fn exists(file_hash_full: &str) -> anyhow::Result<bool> {
        let path = session_db_path(UPLOAD_PREFIX, file_hash_full)?;
        Ok(path.exists())
    }

    /// Open an existing upload session.
    pub fn open(file_hash_full: &str) -> anyhow::Result<Self> {
        let db_path = session_db_path(UPLOAD_PREFIX, file_hash_full)?;

        if !db_path.exists() {
            return Err(anyhow::anyhow!("No upload session found for this file"));
        }

        let conn = Connection::open(&db_path)?;

        // Set exclusive locking to prevent concurrent access
        conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;

        // Try to acquire exclusive lock
        conn.execute("BEGIN EXCLUSIVE TRANSACTION", [])?;
        conn.execute("COMMIT", [])?;

        // Check schema version
        let version: u32 = conn.query_row(
            "SELECT schema_version FROM session_meta WHERE id = 1",
            [],
            |row| row.get(0),
        )?;

        if version != SCHEMA_VERSION {
            return Err(anyhow::anyhow!(
                "Session schema version mismatch (expected {}, found {}). Delete the session to start fresh.",
                SCHEMA_VERSION,
                version
            ));
        }

        // Read total_chunks from session_meta
        let total_chunks: usize = conn.query_row(
            "SELECT total_chunks FROM session_meta WHERE id = 1",
            [],
            |row| row.get(0),
        )?;

        Ok(Self {
            conn,
            db_path,
            total_chunks,
        })
    }

    /// Create a new upload session.
    pub fn create(meta: UploadMeta) -> anyhow::Result<Self> {
        let db_path = session_db_path(UPLOAD_PREFIX, &meta.file_hash_full)?;

        // Delete any existing session
        if db_path.exists() {
            std::fs::remove_file(&db_path)?;
        }

        let conn = Connection::open(&db_path)?;

        // Set exclusive locking to prevent concurrent access
        conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;

        // Create tables
        conn.execute_batch(
            "
            CREATE TABLE session_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                schema_version INTEGER NOT NULL,
                file_path TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                file_hash_full TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                chunk_size INTEGER NOT NULL,
                total_chunks INTEGER NOT NULL,
                pubkey TEXT NOT NULL,
                encryption TEXT NOT NULL,
                relays TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE published_chunks (
                chunk_index INTEGER PRIMARY KEY,
                event_id TEXT NOT NULL,
                chunk_hash TEXT NOT NULL,
                published_at INTEGER NOT NULL
            );
            ",
        )?;

        let now = current_timestamp()?;

        let relays_json = serde_json::to_string(&meta.relays)?;

        conn.execute(
            "INSERT INTO session_meta (id, schema_version, file_path, file_hash, file_hash_full, file_size, chunk_size, total_chunks, pubkey, encryption, relays, created_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                SCHEMA_VERSION,
                meta.file_path.to_string_lossy().to_string(),
                meta.file_hash,
                meta.file_hash_full,
                meta.file_size as i64,
                meta.chunk_size as i64,
                meta.total_chunks as i64,
                meta.pubkey,
                meta.encryption.to_string(),
                relays_json,
                now as i64,
            ],
        )?;

        Ok(Self {
            conn,
            db_path,
            total_chunks: meta.total_chunks,
        })
    }

    /// Record a successfully published chunk.
    pub fn mark_chunk_published(
        &self,
        index: usize,
        event_id: &str,
        chunk_hash: &str,
    ) -> anyhow::Result<()> {
        let now = current_timestamp()?;

        self.conn.execute(
            "INSERT OR REPLACE INTO published_chunks (chunk_index, event_id, chunk_hash, published_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![index as i64, event_id, chunk_hash, now as i64],
        )?;

        Ok(())
    }

    /// Get indices of chunks that still need to be published.
    pub fn get_unpublished_indices(&self) -> anyhow::Result<Vec<usize>> {
        let mut stmt = self
            .conn
            .prepare("SELECT chunk_index FROM published_chunks")?;
        let published: std::collections::HashSet<usize> = stmt
            .query_map([], |row| {
                let idx: i64 = row.get(0)?;
                Ok(idx as usize)
            })?
            .collect::<Result<std::collections::HashSet<usize>, _>>()?;

        let unpublished: Vec<usize> = (0..self.total_chunks)
            .filter(|i| !published.contains(i))
            .collect();

        Ok(unpublished)
    }

    /// Get the count of published chunks.
    pub fn get_published_count(&self) -> anyhow::Result<usize> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM published_chunks",
            [],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    /// Get all published chunk info for building the manifest.
    pub fn get_published_chunks(&self) -> anyhow::Result<Vec<(usize, String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT chunk_index, event_id, chunk_hash FROM published_chunks ORDER BY chunk_index",
        )?;

        let chunks: Vec<(usize, String, String)> = stmt
            .query_map([], |row| {
                let idx: i64 = row.get(0)?;
                let event_id: String = row.get(1)?;
                let hash: String = row.get(2)?;
                Ok((idx as usize, event_id, hash))
            })?
            .collect::<Result<Vec<(usize, String, String)>, _>>()?;

        Ok(chunks)
    }

    /// Delete the session database (call on successful completion).
    pub fn cleanup(self) -> anyhow::Result<()> {
        // Close the connection by dropping it
        drop(self.conn);

        // Delete the database file
        if self.db_path.exists() {
            std::fs::remove_file(&self.db_path)?;
        }

        Ok(())
    }

    /// Delete an upload session without opening it.
    pub fn delete(file_hash_full: &str) -> anyhow::Result<()> {
        delete_session_db(UPLOAD_PREFIX, file_hash_full)
    }
}
