use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

pub struct FileAssembler;

impl FileAssembler {
    pub fn new() -> Self {
        Self
    }

    /// Assemble chunks into a file atomically.
    ///
    /// First verifies all chunks are present, then writes to a temp file
    /// and renames to the final path for atomicity.
    ///
    /// chunks: HashMap of chunk_index -> chunk_data
    pub fn assemble(
        &self,
        chunks: &HashMap<usize, Vec<u8>>,
        total_chunks: usize,
        output_path: &Path,
    ) -> anyhow::Result<()> {
        // 1. Verify all chunks are present before creating any files
        let missing: Vec<usize> = (0..total_chunks)
            .filter(|i| !chunks.contains_key(i))
            .collect();

        if !missing.is_empty() {
            return Err(anyhow::anyhow!(
                "Missing {} chunk(s): {:?}",
                missing.len(),
                missing
            ));
        }

        // 2. Determine temp file path in the same directory for atomic rename
        let parent_dir = output_path.parent().unwrap_or(Path::new("."));
        let file_name = output_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("output");
        let temp_path = parent_dir.join(format!(".{}.tmp.{}", file_name, std::process::id()));

        // 3. Write to temp file
        let write_result = (|| -> anyhow::Result<()> {
            let mut file = File::create(&temp_path)?;

            for i in 0..total_chunks {
                // Safe: we verified all chunks exist above
                let chunk_data = chunks.get(&i).unwrap();
                file.write_all(chunk_data)?;
            }

            // Flush and sync to ensure data is persisted to disk
            file.flush()?;
            file.sync_all()?;

            Ok(())
        })();

        // 4. Handle write errors by cleaning up temp file
        if let Err(e) = write_result {
            // Best effort cleanup of temp file
            let _ = fs::remove_file(&temp_path);
            return Err(e);
        }

        // 5. Atomically rename temp file to final path
        if let Err(e) = fs::rename(&temp_path, output_path) {
            // Clean up temp file on rename failure
            let _ = fs::remove_file(&temp_path);
            return Err(anyhow::anyhow!(
                "Failed to rename temp file to '{}': {}",
                output_path.display(),
                e
            ));
        }

        Ok(())
    }
}

impl Default for FileAssembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tempfile::TempDir;

    #[test]
    fn test_assemble_success() {
        let temp_dir = TempDir::new().unwrap();
        let output_path = temp_dir.path().join("output.bin");

        let mut chunks = HashMap::new();
        chunks.insert(0, b"Hello, ".to_vec());
        chunks.insert(1, b"World!".to_vec());

        let assembler = FileAssembler::new();
        assembler.assemble(&chunks, 2, &output_path).unwrap();

        let content = std::fs::read_to_string(&output_path).unwrap();
        assert_eq!(content, "Hello, World!");
    }

    #[test]
    fn test_assemble_missing_chunks_error() {
        let temp_dir = TempDir::new().unwrap();
        let output_path = temp_dir.path().join("output.bin");

        let mut chunks = HashMap::new();
        chunks.insert(0, b"chunk0".to_vec());
        // Missing chunks 1 and 2
        chunks.insert(3, b"chunk3".to_vec());

        let assembler = FileAssembler::new();
        let result = assembler.assemble(&chunks, 4, &output_path);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Missing"));
        assert!(err_msg.contains("1"));
        assert!(err_msg.contains("2"));

        // File should not exist after error
        assert!(!output_path.exists());
    }

    #[test]
    fn test_assemble_no_partial_file_on_missing() {
        let temp_dir = TempDir::new().unwrap();
        let output_path = temp_dir.path().join("output.bin");

        let mut chunks = HashMap::new();
        chunks.insert(0, b"chunk0".to_vec());
        // Missing chunk 1

        let assembler = FileAssembler::new();
        let _ = assembler.assemble(&chunks, 2, &output_path);

        // No file should be created
        assert!(!output_path.exists());

        // No temp files should be left behind
        let temp_files: Vec<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(temp_files.is_empty());
    }
}
