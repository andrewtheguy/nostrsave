use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

pub struct FileAssembler;

impl FileAssembler {
    pub fn new() -> Self {
        Self
    }

    /// Assemble chunks into a file
    /// chunks: HashMap of chunk_index -> chunk_data
    pub fn assemble(
        &self,
        chunks: &HashMap<usize, Vec<u8>>,
        total_chunks: usize,
        output_path: &Path,
    ) -> anyhow::Result<()> {
        let mut file = std::fs::File::create(output_path)?;

        for i in 0..total_chunks {
            let chunk_data = chunks
                .get(&i)
                .ok_or_else(|| anyhow::anyhow!("Missing chunk {}", i))?;
            file.write_all(chunk_data)?;
        }

        file.flush()?;
        Ok(())
    }
}

impl Default for FileAssembler {
    fn default() -> Self {
        Self::new()
    }
}
