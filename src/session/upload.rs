use crate::config::EncryptionAlgorithm;
use rusqlite::{params, Connection};
use std::fs::File;
use std::path::PathBuf;

use super::db::{
    acquire_session_lock, current_timestamp, delete_session_db, remove_session_lock,
    session_db_path, SCHEMA_VERSION,
};

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
    #[allow(dead_code)] // Lock held for session lifetime, released on drop
    lock: File,
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

        // Acquire file lock BEFORE opening connection
        let lock = acquire_session_lock(&db_path)?;

        let conn = Connection::open(&db_path)?;

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
            lock,
            db_path,
            total_chunks,
        })
    }

    /// Create a new upload session.
    pub fn create(meta: UploadMeta) -> anyhow::Result<Self> {
        let db_path = session_db_path(UPLOAD_PREFIX, &meta.file_hash_full)?;

        // Acquire lock FIRST to prevent race with other processes.
        // This creates the .db.lock file and holds exclusive access.
        let lock = acquire_session_lock(&db_path)?;

        // Now safe to delete any existing DB under the held lock
        if db_path.exists() {
            std::fs::remove_file(&db_path)?;
        }

        // Create and open DB file while holding the lock
        let conn = Connection::open(&db_path)?;

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

        // Non-UTF-8 paths are rejected; lossy conversion could corrupt the stored path
        let file_path_str = meta
            .file_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("File path contains invalid UTF-8"))?
            .to_string();

        conn.execute(
            "INSERT INTO session_meta (id, schema_version, file_path, file_hash, file_hash_full, file_size, chunk_size, total_chunks, pubkey, encryption, relays, created_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                SCHEMA_VERSION,
                file_path_str,
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
            lock,
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

    /// Get the relay list saved in this upload session.
    pub fn get_relays(&self) -> anyhow::Result<Vec<String>> {
        let relays_json: String = self.conn.query_row(
            "SELECT relays FROM session_meta WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        let relays: Vec<String> = serde_json::from_str(&relays_json)?;
        Ok(relays)
    }

    /// Delete the session database (call on successful completion).
    pub fn cleanup(self) -> anyhow::Result<()> {
        let db_path = self.db_path.clone();

        // Drop lock first (releases file lock)
        drop(self.lock);
        // Close the connection
        drop(self.conn);

        // Delete the database file
        if db_path.exists() {
            std::fs::remove_file(&db_path)?;
        }

        // Delete the lock file
        remove_session_lock(&db_path)?;

        Ok(())
    }

    /// Delete an upload session without opening it.
    /// Acquires the session lock first to ensure no other process is using it.
    pub fn delete(file_hash_full: &str) -> anyhow::Result<()> {
        let db_path = session_db_path(UPLOAD_PREFIX, file_hash_full)?;

        // Acquire lock to ensure no other process is using this session.
        // If another process holds the lock, this will fail immediately.
        let lock = acquire_session_lock(&db_path)?;

        // Delete the DB while holding the lock
        delete_session_db(UPLOAD_PREFIX, file_hash_full)?;

        // Release lock (drop) and remove lock file
        drop(lock);
        remove_session_lock(&db_path)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_session_persists_relay_list_for_resume() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("file.bin");
        std::fs::write(&file_path, b"hello").unwrap();

        // Unique-ish identifier to avoid collisions in the shared temp sessions dir
        let file_hash_full = format!(
            "test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let relays = vec![
            "wss://relay1.example.com".to_string(),
            "wss://relay2.example.com".to_string(),
        ];

        struct CleanupGuard {
            file_hash_full: String,
        }
        impl Drop for CleanupGuard {
            fn drop(&mut self) {
                let _ = UploadSession::delete(&self.file_hash_full);
            }
        }
        let _guard = CleanupGuard {
            file_hash_full: file_hash_full.clone(),
        };

        let meta = UploadMeta {
            file_path: file_path.clone(),
            file_hash: "deadbeef".to_string(),
            file_hash_full: file_hash_full.clone(),
            file_size: std::fs::metadata(&file_path).unwrap().len(),
            chunk_size: 1024,
            total_chunks: 1,
            pubkey: "npub1test".to_string(),
            encryption: EncryptionAlgorithm::Aes256Gcm,
            relays: relays.clone(),
        };

        let session = UploadSession::create(meta).unwrap();
        assert_eq!(session.get_relays().unwrap(), relays);
        drop(session); // keep DB for resume; release lock by dropping the session

        // Ensure resume path can read the relays back after reopening.
        let reopened = UploadSession::open(&file_hash_full).unwrap();
        assert_eq!(reopened.get_relays().unwrap(), relays);
        reopened.cleanup().unwrap();
    }
}
