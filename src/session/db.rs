use fs2::FileExt;
use sha2::{Digest, Sha512};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Current schema version. Sessions with different versions are not compatible.
pub const SCHEMA_VERSION: u32 = 1;

/// Compute SHA512 hash of a file for session DB naming.
pub fn compute_file_sha512(path: &Path) -> anyhow::Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha512::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Compute SHA512 hash of a string (for download sessions where we don't have the file).
pub fn compute_hash_sha512(input: &str) -> String {
    let mut hasher = Sha512::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Get the sessions directory in the system temp directory.
/// Creates the directory if it doesn't exist.
pub fn sessions_dir() -> anyhow::Result<PathBuf> {
    let dir = std::env::temp_dir().join("nostrsave-sessions");

    if !dir.exists() {
        fs::create_dir_all(&dir)?;
    }

    Ok(dir)
}

/// Compute session database path from hash.
/// Uses first 32 characters of the hash for the filename.
pub fn session_db_path(prefix: &str, hash_full: &str) -> anyhow::Result<PathBuf> {
    let dir = sessions_dir()?;
    let hash_suffix = &hash_full[..32.min(hash_full.len())];
    Ok(dir.join(format!("{}_{}.db", prefix, hash_suffix)))
}

/// Delete a session database file if it exists.
pub fn delete_session_db(prefix: &str, hash_full: &str) -> anyhow::Result<()> {
    let path = session_db_path(prefix, hash_full)?;
    if path.exists() {
        fs::remove_file(&path)?;
    }
    Ok(())
}

/// Get current Unix timestamp in seconds.
/// Returns an error if system clock is before Unix epoch (requires user to fix system clock).
pub fn current_timestamp() -> anyhow::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| anyhow::anyhow!("system clock error: time is before Unix epoch ({})", e))
}

/// Acquire exclusive lock using a separate .lock file.
/// The lock is held as long as the returned File is not dropped.
/// Using a separate file avoids conflicts with SQLite's internal locking.
pub fn acquire_session_lock(db_path: &Path) -> anyhow::Result<File> {
    let lock_path = db_path.with_extension("db.lock");

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;

    file.try_lock_exclusive().map_err(|_| {
        anyhow::anyhow!(
            "Another session is using this file. \
             Wait for it to complete or delete the session."
        )
    })?;

    Ok(file)
}

/// Remove the lock file when session is cleaned up.
pub fn remove_session_lock(db_path: &Path) -> anyhow::Result<()> {
    let lock_path = db_path.with_extension("db.lock");
    if lock_path.exists() {
        fs::remove_file(&lock_path)?;
    }
    Ok(())
}
