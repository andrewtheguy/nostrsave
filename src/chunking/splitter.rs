use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

pub struct FileChunker {
    chunk_size: usize,
}

#[derive(Debug, Clone)]
pub struct Chunk {
    pub index: usize,
    pub data: Vec<u8>,
    pub hash: String,
}

impl FileChunker {
    pub fn new(chunk_size: usize) -> Self {
        Self { chunk_size }
    }

    /// Split a file into chunks and compute hashes
    /// Returns (file_hash, chunks)
    pub fn split_file(&self, path: &Path) -> anyhow::Result<(String, Vec<Chunk>)> {
        let mut file = std::fs::File::open(path)?;
        let mut file_hasher = Sha256::new();
        let mut chunks = Vec::new();
        let mut buffer = vec![0u8; self.chunk_size];
        let mut index = 0;

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }

            let chunk_data = buffer[..bytes_read].to_vec();
            file_hasher.update(&chunk_data);

            let mut chunk_hasher = Sha256::new();
            chunk_hasher.update(&chunk_data);
            let chunk_hash = hex::encode(chunk_hasher.finalize());

            chunks.push(Chunk {
                index,
                data: chunk_data,
                hash: format!("sha256:{}", chunk_hash),
            });

            index += 1;
        }

        let file_hash = format!("sha256:{}", hex::encode(file_hasher.finalize()));
        Ok((file_hash, chunks))
    }

    /// Compute hash of a file without splitting
    pub fn compute_file_hash(&self, path: &Path) -> anyhow::Result<String> {
        let mut file = std::fs::File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; self.chunk_size];

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
    }
}
