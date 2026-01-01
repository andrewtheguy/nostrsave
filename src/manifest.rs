use serde::{Deserialize, Serialize};
use std::path::Path;

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
    ) -> Self {
        let total_chunks = file_size.div_ceil(chunk_size as u64) as usize;
        Self {
            version: 1,
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
        }
    }

    pub fn add_chunk(&mut self, index: usize, event_id: String, hash: String) {
        self.chunks.push(ChunkInfo {
            index,
            event_id,
            hash,
        });
    }

    pub fn save_to_file(&self, path: &Path) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn load_from_file(path: &Path) -> anyhow::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&json)?)
    }
}
