use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
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

/// Iterator that yields chunks one-by-one while computing file hash incrementally
pub struct ChunkIterator {
    reader: BufReader<File>,
    buffer: Vec<u8>,
    index: usize,
    file_hasher: Sha256,
    finished: bool,
}

/// Result of iterating through all chunks
pub struct ChunkIteratorResult {
    /// The final file hash (available after iteration completes)
    pub file_hash: String,
    // Total number of chunks processed, for further use
    // pub total_chunks: usize,
}

impl ChunkIterator {
    fn new(file: File, chunk_size: usize) -> Self {
        Self {
            reader: BufReader::new(file),
            buffer: vec![0u8; chunk_size],
            index: 0,
            file_hasher: Sha256::new(),
            finished: false,
        }
    }

    /// Consume the iterator and return the final file hash and chunk count.
    /// Call this after iterating through all chunks.
    pub fn finalize(self) -> ChunkIteratorResult {
        ChunkIteratorResult {
            file_hash: format!("sha256:{}", hex::encode(self.file_hasher.finalize())),
            //total_chunks: self.index,
        }
    }

    // Get the current chunk count (chunks yielded so far), for futher use.
    // pub fn chunks_yielded(&self) -> usize {
    //     self.index
    // }
}

impl Iterator for ChunkIterator {
    type Item = std::io::Result<Chunk>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        match self.reader.read(&mut self.buffer) {
            Ok(0) => {
                self.finished = true;
                None
            }
            Ok(bytes_read) => {
                let chunk_data = self.buffer[..bytes_read].to_vec();
                self.file_hasher.update(&chunk_data);

                let mut chunk_hasher = Sha256::new();
                chunk_hasher.update(&chunk_data);
                let chunk_hash = hex::encode(chunk_hasher.finalize());

                let chunk = Chunk {
                    index: self.index,
                    data: chunk_data,
                    hash: format!("sha256:{}", chunk_hash),
                };

                self.index += 1;
                Some(Ok(chunk))
            }
            Err(e) => {
                self.finished = true;
                Some(Err(e))
            }
        }
    }
}

impl FileChunker {
    pub fn new(chunk_size: usize) -> anyhow::Result<Self> {
        if chunk_size == 0 {
            return Err(anyhow::anyhow!("chunk_size must be > 0"));
        }
        Ok(Self { chunk_size })
    }

    /// Split a file into chunks using a streaming iterator.
    /// Returns a ChunkIterator that yields chunks one-by-one.
    /// Call `finalize()` on the iterator after processing to get the file hash.
    ///
    /// # Example
    /// ```ignore
    /// let chunker = FileChunker::new(65408)?;
    /// let mut iter = chunker.split_file_iter(&path)?;
    ///
    /// for chunk_result in &mut iter {
    ///     let chunk = chunk_result?;
    ///     // Process chunk...
    /// }
    ///
    /// let result = iter.finalize();
    /// println!("File hash: {}", result.file_hash);
    /// ```
    pub fn split_file_iter(&self, path: &Path) -> anyhow::Result<ChunkIterator> {
        let file = File::open(path)?;
        Ok(ChunkIterator::new(file, self.chunk_size))
    }

    /// Split a file into chunks and compute hashes.
    /// Returns (file_hash, chunks).
    ///
    /// WARNING: This loads all chunks into memory. For large files,
    /// use `split_file_iter()` instead to process chunks one-by-one.
    pub fn split_file(&self, path: &Path) -> anyhow::Result<(String, Vec<Chunk>)> {
        let mut iter = self.split_file_iter(path)?;
        let mut chunks = Vec::new();

        for chunk_result in &mut iter {
            chunks.push(chunk_result?);
        }

        let result = iter.finalize();
        Ok((result.file_hash, chunks))
    }

    /// Compute hash of a file without splitting
    pub fn compute_file_hash(&self, path: &Path) -> anyhow::Result<String> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; self.chunk_size];

        loop {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_split_file_iter_matches_split_file() {
        // Create a temp file with known content
        let mut file = NamedTempFile::new().unwrap();
        let content = b"Hello, World! This is test content for chunking.";
        file.write_all(content).unwrap();

        let chunker = FileChunker::new(16).unwrap();

        // Get results from both methods
        let (hash1, chunks1) = chunker.split_file(file.path()).unwrap();

        let mut iter = chunker.split_file_iter(file.path()).unwrap();
        let mut chunks2 = Vec::new();
        for chunk_result in &mut iter {
            chunks2.push(chunk_result.unwrap());
        }
        let result = iter.finalize();

        // Verify they match
        assert_eq!(hash1, result.file_hash);
        assert_eq!(chunks1.len(), chunks2.len());

        for (c1, c2) in chunks1.iter().zip(chunks2.iter()) {
            assert_eq!(c1.index, c2.index);
            assert_eq!(c1.hash, c2.hash);
            assert_eq!(c1.data, c2.data);
        }
    }

    #[test]
    fn test_iterator_yields_correct_count() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"0123456789ABCDEF").unwrap(); // 16 bytes

        let chunker = FileChunker::new(4).unwrap();
        let mut iter = chunker.split_file_iter(file.path()).unwrap();

        let mut count = 0;
        while iter.next().is_some() {
            count += 1;
        }
        assert_eq!(count, 4); // 16 bytes / 4 bytes per chunk = 4 chunks
    }

    #[test]
    fn test_empty_file() {
        let file = NamedTempFile::new().unwrap();

        let chunker = FileChunker::new(1024).unwrap();
        let mut iter = chunker.split_file_iter(file.path()).unwrap();

        assert!(iter.next().is_none());
        // Empty file should still produce a valid hash
        let result = iter.finalize();
        assert!(!result.file_hash.is_empty());
    }
}
