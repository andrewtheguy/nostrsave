use crate::config::EncryptionAlgorithm;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

/// Current manifest version
pub const CURRENT_MANIFEST_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u8,
    pub file_name: String,
    pub file_hash: String,
    pub file_size: u64,
    pub chunk_size: usize,
    pub total_chunks: usize,
    pub created_at: u64,
    pub pubkey: String,
    pub chunks: Vec<ChunkInfo>,
    pub relays: Vec<String>,
    pub encryption: EncryptionAlgorithm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkInfo {
    pub index: usize,
    pub event_id: String,
    pub hash: String,
}

impl Manifest {
    pub fn new(
        file_name: String,
        file_hash: String,
        file_size: u64,
        chunk_size: usize,
        pubkey: String,
        relays: Vec<String>,
        encryption: EncryptionAlgorithm,
    ) -> Self {
        let total_chunks = file_size.div_ceil(chunk_size as u64) as usize;
        Self {
            version: CURRENT_MANIFEST_VERSION,
            file_name,
            file_hash,
            file_size,
            chunk_size,
            total_chunks,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            pubkey,
            chunks: Vec::with_capacity(total_chunks),
            relays,
            encryption,
        }
    }

    /// Add a chunk to the manifest with validation.
    ///
    /// Returns an error if:
    /// - The index is out of bounds (>= total_chunks)
    /// - A chunk with the same index already exists
    pub fn add_chunk(&mut self, index: usize, event_id: String, hash: String) -> anyhow::Result<()> {
        // Validate index is within bounds
        if index >= self.total_chunks {
            return Err(anyhow::anyhow!(
                "Chunk index {} is out of bounds (total_chunks = {})",
                index,
                self.total_chunks
            ));
        }

        // Check for duplicate index
        if self.chunks.iter().any(|c| c.index == index) {
            return Err(anyhow::anyhow!(
                "Duplicate chunk index {}: chunk already exists",
                index
            ));
        }

        self.chunks.push(ChunkInfo {
            index,
            event_id,
            hash,
        });

        Ok(())
    }

    /// Save manifest to file atomically.
    ///
    /// Writes to a temp file first, syncs to disk, then renames to final path.
    pub fn save_to_file(&self, path: &Path) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;

        // Determine temp file path in same directory for atomic rename
        let parent_dir = path.parent().unwrap_or(Path::new("."));
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("manifest");
        let temp_path = parent_dir.join(format!(".{}.tmp.{}", file_name, std::process::id()));

        // Write to temp file
        let write_result = (|| -> anyhow::Result<()> {
            let mut file = File::create(&temp_path)?;
            file.write_all(json.as_bytes())?;
            file.flush()?;
            file.sync_all()?;
            Ok(())
        })();

        // Handle write errors by cleaning up temp file
        if let Err(e) = write_result {
            let _ = fs::remove_file(&temp_path);
            return Err(e);
        }

        // Atomically rename temp file to final path
        if let Err(e) = fs::rename(&temp_path, path) {
            let _ = fs::remove_file(&temp_path);
            return Err(anyhow::anyhow!(
                "Failed to rename temp file to '{}': {}",
                path.display(),
                e
            ));
        }

        Ok(())
    }

    pub fn load_from_file(path: &Path) -> anyhow::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let manifest: Self = serde_json::from_str(&json)?;

        if manifest.version != CURRENT_MANIFEST_VERSION {
            return Err(anyhow::anyhow!(
                "Unsupported manifest version: expected {}, got {}",
                CURRENT_MANIFEST_VERSION,
                manifest.version
            ));
        }

        Ok(manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_manifest() -> Manifest {
        Manifest::new(
            "test.bin".to_string(),
            "sha256:abc123".to_string(),
            1000,
            100,
            "npub1test".to_string(),
            vec!["wss://relay.example.com".to_string()],
            EncryptionAlgorithm::None,
        )
    }

    #[test]
    fn test_add_chunk_success() {
        let mut manifest = create_test_manifest();
        assert!(manifest.add_chunk(0, "note1abc".to_string(), "sha256:chunk0".to_string()).is_ok());
        assert!(manifest.add_chunk(5, "note1def".to_string(), "sha256:chunk5".to_string()).is_ok());
        assert_eq!(manifest.chunks.len(), 2);
    }

    #[test]
    fn test_add_chunk_out_of_bounds() {
        let mut manifest = create_test_manifest();
        // total_chunks = 10 (1000 / 100), so index 10 is out of bounds
        let result = manifest.add_chunk(10, "note1xxx".to_string(), "sha256:chunkX".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("out of bounds"));
    }

    #[test]
    fn test_add_chunk_duplicate_index() {
        let mut manifest = create_test_manifest();
        manifest.add_chunk(3, "note1first".to_string(), "sha256:chunk3".to_string()).unwrap();

        let result = manifest.add_chunk(3, "note1second".to_string(), "sha256:chunk3dup".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Duplicate"));
    }

    #[test]
    fn test_save_and_load_file() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("manifest.nostrsave");

        let mut manifest = create_test_manifest();
        manifest.add_chunk(0, "note1abc".to_string(), "sha256:chunk0".to_string()).unwrap();
        manifest.save_to_file(&path).unwrap();

        let loaded = Manifest::load_from_file(&path).unwrap();
        assert_eq!(loaded.file_name, manifest.file_name);
        assert_eq!(loaded.file_hash, manifest.file_hash);
        assert_eq!(loaded.encryption, manifest.encryption);
        assert_eq!(loaded.chunks.len(), 1);
        assert_eq!(loaded.chunks[0].index, 0);
    }

    #[test]
    fn test_save_atomic_no_partial_on_dir_not_exists() {
        // Trying to save to a non-existent directory should fail cleanly
        let path = Path::new("/nonexistent/dir/manifest.nostrsave");
        let manifest = create_test_manifest();

        let result = manifest.save_to_file(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_rejects_unsupported_version() {
        use std::io::Write;

        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("manifest.nostrsave");

        // Create a manifest JSON with an unsupported version
        let json = r#"{
            "version": 99,
            "file_name": "test.bin",
            "file_hash": "sha256:abc123",
            "file_size": 1000,
            "chunk_size": 100,
            "total_chunks": 10,
            "created_at": 1234567890,
            "pubkey": "npub1test",
            "chunks": [],
            "relays": ["wss://relay.example.com"],
            "encryption": "none"
        }"#;

        let mut file = File::create(&path).unwrap();
        file.write_all(json.as_bytes()).unwrap();
        file.flush().unwrap();
        drop(file);

        let result = Manifest::load_from_file(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported manifest version"));
    }
}
