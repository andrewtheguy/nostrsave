use crate::config::EncryptionAlgorithm;
use crate::manifest::Manifest;
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::path::PathBuf;

use super::db::{current_timestamp, delete_session_db, session_db_path, SCHEMA_VERSION};

const DOWNLOAD_PREFIX: &str = "download";

/// Metadata for creating a download session.
pub struct DownloadMeta {
    pub file_hash: String,
    pub file_hash_full: String,
    pub file_name: String,
    pub file_size: u64,
    pub total_chunks: usize,
    pub encryption: EncryptionAlgorithm,
    pub manifest: Manifest,
    pub output_path: PathBuf,
}

/// Download session for tracking downloaded chunks.
pub struct DownloadSession {
    conn: Connection,
    db_path: PathBuf,
    pub total_chunks: usize,
}

impl DownloadSession {
    /// Check if a download session exists for the given file hash.
    pub fn exists(file_hash_full: &str) -> anyhow::Result<bool> {
        let path = session_db_path(DOWNLOAD_PREFIX, file_hash_full)?;
        Ok(path.exists())
    }

    /// Open an existing download session.
    pub fn open(file_hash_full: &str) -> anyhow::Result<Self> {
        let db_path = session_db_path(DOWNLOAD_PREFIX, file_hash_full)?;

        if !db_path.exists() {
            return Err(anyhow::anyhow!("No download session found for this file"));
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

    /// Create a new download session.
    pub fn create(meta: DownloadMeta) -> anyhow::Result<Self> {
        let db_path = session_db_path(DOWNLOAD_PREFIX, &meta.file_hash_full)?;

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
                file_hash TEXT NOT NULL,
                file_hash_full TEXT NOT NULL,
                file_name TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                total_chunks INTEGER NOT NULL,
                encryption TEXT NOT NULL,
                manifest_json TEXT NOT NULL,
                output_path TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE downloaded_chunks (
                chunk_index INTEGER PRIMARY KEY,
                data BLOB NOT NULL,
                chunk_hash TEXT NOT NULL,
                downloaded_at INTEGER NOT NULL
            );
            ",
        )?;

        let now = current_timestamp()?;

        let manifest_json = serde_json::to_string(&meta.manifest)?;

        conn.execute(
            "INSERT INTO session_meta (id, schema_version, file_hash, file_hash_full, file_name, file_size, total_chunks, encryption, manifest_json, output_path, created_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                SCHEMA_VERSION,
                meta.file_hash,
                meta.file_hash_full,
                meta.file_name,
                meta.file_size as i64,
                meta.total_chunks as i64,
                meta.encryption.to_string(),
                manifest_json,
                meta.output_path.to_string_lossy().to_string(),
                now as i64,
            ],
        )?;

        Ok(Self {
            conn,
            db_path,
            total_chunks: meta.total_chunks,
        })
    }

    /// Store a downloaded chunk.
    pub fn store_chunk(&self, index: usize, data: &[u8], chunk_hash: &str) -> anyhow::Result<()> {
        let now = current_timestamp()?;

        self.conn.execute(
            "INSERT OR REPLACE INTO downloaded_chunks (chunk_index, data, chunk_hash, downloaded_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![index as i64, data, chunk_hash, now as i64],
        )?;

        Ok(())
    }

    /// Get indices of chunks that still need to be downloaded.
    pub fn get_missing_indices(&self) -> anyhow::Result<Vec<usize>> {
        let mut stmt = self
            .conn
            .prepare("SELECT chunk_index FROM downloaded_chunks")?;
        let downloaded: std::collections::HashSet<usize> = stmt
            .query_map([], |row| {
                let idx: i64 = row.get(0)?;
                Ok(idx as usize)
            })?
            .collect::<Result<std::collections::HashSet<usize>, _>>()?;

        let missing: Vec<usize> = (0..self.total_chunks)
            .filter(|i| !downloaded.contains(i))
            .collect();

        Ok(missing)
    }

    /// Get the count of downloaded chunks.
    pub fn get_downloaded_count(&self) -> anyhow::Result<usize> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM downloaded_chunks",
            [],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    /// Get all downloaded chunks for file assembly.
    pub fn get_all_chunks(&self) -> anyhow::Result<HashMap<usize, Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT chunk_index, data FROM downloaded_chunks ORDER BY chunk_index")?;

        let chunks: HashMap<usize, Vec<u8>> = stmt
            .query_map([], |row| {
                let idx: i64 = row.get(0)?;
                let data: Vec<u8> = row.get(1)?;
                Ok((idx as usize, data))
            })?
            .collect::<Result<HashMap<usize, Vec<u8>>, _>>()?;

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

    /// Delete a download session without opening it.
    pub fn delete(file_hash_full: &str) -> anyhow::Result<()> {
        delete_session_db(DOWNLOAD_PREFIX, file_hash_full)
    }
}
