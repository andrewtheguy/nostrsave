use crate::config::{EncryptionAlgorithm, FILE_INDEX_EVENT_KIND};
use nostr_sdk::prelude::*;
use serde::{Deserialize, Deserializer, Serialize};

/// Identifier for the file index replaceable event (page 1)
pub const FILE_INDEX_IDENTIFIER: &str = "nostrsave-index";

/// Current file index version
pub const CURRENT_FILE_INDEX_VERSION: u8 = 2;

/// Maximum entries per index page before archiving
pub const MAX_ENTRIES_PER_PAGE: usize = 1000;

/// Expected length of SHA-256 hash in hex (64 characters)
const SHA256_HEX_LEN: usize = 64;

/// A single entry in the file index
#[derive(Debug, Clone, Serialize)]
pub struct FileIndexEntry {
    file_hash: String,
    file_name: String,
    file_size: u64,
    uploaded_at: u64,
    encryption: EncryptionAlgorithm,
}

impl FileIndexEntry {
    /// Create a new validated file index entry.
    ///
    /// # Errors
    /// Returns an error if:
    /// - `file_hash` doesn't start with "sha256:" or has invalid hex
    /// - `file_name` is empty or contains path separators
    /// - `file_size` is zero
    /// - `uploaded_at` is zero
    pub fn new(
        file_hash: String,
        file_name: String,
        file_size: u64,
        uploaded_at: u64,
        encryption: EncryptionAlgorithm,
    ) -> anyhow::Result<Self> {
        // Validate file_hash format: "sha256:<64 hex chars>"
        if !file_hash.starts_with("sha256:") {
            return Err(anyhow::anyhow!(
                "Invalid file_hash: must start with 'sha256:', got '{}'",
                file_hash
            ));
        }
        let hex_part = &file_hash[7..];
        if hex_part.len() != SHA256_HEX_LEN {
            return Err(anyhow::anyhow!(
                "Invalid file_hash: expected {} hex characters, got {}",
                SHA256_HEX_LEN,
                hex_part.len()
            ));
        }
        if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(anyhow::anyhow!(
                "Invalid file_hash: contains non-hex characters"
            ));
        }

        // Validate file_name: non-empty, no path separators, no traversal, no control chars
        if file_name.is_empty() {
            return Err(anyhow::anyhow!("Invalid file_name: cannot be empty"));
        }
        if file_name.contains('/') || file_name.contains('\\') {
            return Err(anyhow::anyhow!(
                "Invalid file_name: cannot contain path separators"
            ));
        }
        // Reject directory traversal attempts
        if file_name == ".." || file_name == "." {
            return Err(anyhow::anyhow!(
                "Invalid file_name: cannot be '.' or '..'"
            ));
        }
        // Reject NUL bytes
        if file_name.contains('\0') {
            return Err(anyhow::anyhow!(
                "Invalid file_name: cannot contain NUL bytes"
            ));
        }
        // Reject control characters (ASCII 0x00-0x1F and 0x7F)
        if file_name.chars().any(|c| c.is_control()) {
            return Err(anyhow::anyhow!(
                "Invalid file_name: cannot contain control characters"
            ));
        }

        // Validate file_size > 0
        if file_size == 0 {
            return Err(anyhow::anyhow!("Invalid file_size: must be greater than 0"));
        }

        // Validate uploaded_at > 0
        if uploaded_at == 0 {
            return Err(anyhow::anyhow!(
                "Invalid uploaded_at: must be a valid Unix timestamp"
            ));
        }

        Ok(Self {
            file_hash,
            file_name,
            file_size,
            uploaded_at,
            encryption,
        })
    }

    /// Get the file hash
    #[must_use]
    pub fn file_hash(&self) -> &str {
        &self.file_hash
    }

    /// Get the file name
    #[must_use]
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    /// Get the file size
    #[must_use]
    pub fn file_size(&self) -> u64 {
        self.file_size
    }

    /// Get the upload timestamp
    #[must_use]
    pub fn uploaded_at(&self) -> u64 {
        self.uploaded_at
    }

    /// Get the encryption algorithm
    #[must_use]
    pub fn encryption(&self) -> EncryptionAlgorithm {
        self.encryption
    }
}

impl<'de> Deserialize<'de> for FileIndexEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize into a raw struct first
        #[derive(Deserialize)]
        struct RawFileIndexEntry {
            file_hash: String,
            file_name: String,
            file_size: u64,
            uploaded_at: u64,
            encryption: EncryptionAlgorithm,
        }

        let raw = RawFileIndexEntry::deserialize(deserializer)?;

        // Validate using the constructor
        FileIndexEntry::new(
            raw.file_hash,
            raw.file_name,
            raw.file_size,
            raw.uploaded_at,
            raw.encryption,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// The file index containing all uploaded files for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIndex {
    version: u8,
    entries: Vec<FileIndexEntry>,
    page: u32,
    total_pages: u32,
}

impl FileIndex {
    /// Create a new empty file index
    pub fn new() -> Self {
        Self {
            version: CURRENT_FILE_INDEX_VERSION,
            entries: Vec::new(),
            page: 1,
            total_pages: 1,
        }
    }

    /// Create a file index for a specific page
    pub fn new_page(page: u32, total_pages: u32) -> Self {
        Self {
            version: CURRENT_FILE_INDEX_VERSION,
            entries: Vec::new(),
            page,
            total_pages,
        }
    }

    /// Add an entry, replacing any existing entry with the same file_hash
    pub fn add_entry(&mut self, entry: FileIndexEntry) {
        if let Some(pos) = self
            .entries
            .iter()
            .position(|e| e.file_hash() == entry.file_hash())
        {
            // Update existing entry in-place
            self.entries[pos] = entry;
        } else {
            // New entry
            self.entries.push(entry);
        }
    }

    /// Get number of files in the index
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if index is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get the index version
    #[must_use]
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Get read-only access to entries
    #[must_use]
    pub fn entries(&self) -> &[FileIndexEntry] {
        &self.entries
    }

    /// Get the page number (1 = newest/current)
    #[must_use]
    pub fn page(&self) -> u32 {
        self.page
    }

    /// Get the total number of pages
    #[must_use]
    pub fn total_pages(&self) -> u32 {
        self.total_pages
    }

    /// Check if this index needs archiving (too many entries)
    #[must_use]
    pub fn needs_archiving(&self) -> bool {
        self.entries.len() > MAX_ENTRIES_PER_PAGE
    }

    /// Get the d-tag identifier for this index page
    #[must_use]
    pub fn get_identifier(&self) -> String {
        if self.page == 1 {
            FILE_INDEX_IDENTIFIER.to_string()
        } else {
            format!("{}-page-{}", FILE_INDEX_IDENTIFIER, self.page)
        }
    }
}

impl Default for FileIndex {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a Nostr event for the file index
pub fn create_file_index_event(index: &FileIndex) -> anyhow::Result<EventBuilder> {
    let content = serde_json::to_string(index)?;

    let tags = vec![
        Tag::identifier(index.get_identifier()),
    ];

    Ok(EventBuilder::new(Kind::Custom(FILE_INDEX_EVENT_KIND), content).tags(tags))
}

/// Create a filter to query for a specific page of a user's file index
pub fn create_file_index_page_filter(pubkey: &PublicKey, page: u32) -> Filter {
    let identifier = if page == 1 {
        FILE_INDEX_IDENTIFIER.to_string()
    } else {
        format!("{}-page-{}", FILE_INDEX_IDENTIFIER, page)
    };

    Filter::new()
        .kind(Kind::Custom(FILE_INDEX_EVENT_KIND))
        .author(*pubkey)
        .identifier(identifier)
        .limit(1)
}

/// Parse a file index from a Nostr event
pub fn parse_file_index_event(event: &Event) -> anyhow::Result<FileIndex> {
    if event.kind != Kind::Custom(FILE_INDEX_EVENT_KIND) {
        return Err(anyhow::anyhow!(
            "Invalid event kind: expected {}, got {}",
            FILE_INDEX_EVENT_KIND,
            event.kind.as_u16()
        ));
    }

    let index: FileIndex = serde_json::from_str(&event.content)?;

    if index.version() != CURRENT_FILE_INDEX_VERSION {
        return Err(anyhow::anyhow!(
            "Unsupported file index version: expected {}, got {}",
            CURRENT_FILE_INDEX_VERSION,
            index.version()
        ));
    }

    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Valid SHA-256 hash for testing (64 hex chars)
    const TEST_HASH: &str = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn test_file_index_new() {
        let index = FileIndex::new();
        assert_eq!(index.version(), CURRENT_FILE_INDEX_VERSION);
        assert!(index.is_empty());
        assert_eq!(index.page(), 1);
        assert_eq!(index.total_pages(), 1);
    }

    #[test]
    fn test_file_index_get_identifier() {
        let index = FileIndex::new();
        assert_eq!(index.get_identifier(), "nostrsave-index");

        let page2 = FileIndex::new_page(2, 3);
        assert_eq!(page2.get_identifier(), "nostrsave-index-page-2");

        let page5 = FileIndex::new_page(5, 10);
        assert_eq!(page5.get_identifier(), "nostrsave-index-page-5");
    }

    #[test]
    fn test_file_index_needs_archiving() {
        let mut index = FileIndex::new();
        assert!(!index.needs_archiving());

        // Add MAX_ENTRIES_PER_PAGE entries - should not need archiving
        for i in 0..MAX_ENTRIES_PER_PAGE {
            let hash = format!(
                "sha256:{:064x}",
                i
            );
            let entry = FileIndexEntry::new(
                hash,
                format!("file{i}.txt"),
                1024,
                1234567890,
                EncryptionAlgorithm::Nip44,
            )
            .unwrap();
            index.add_entry(entry);
        }
        assert!(!index.needs_archiving());

        // Add one more - should need archiving
        let entry = FileIndexEntry::new(
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
            "overflow.txt".to_string(),
            1024,
            1234567890,
            EncryptionAlgorithm::Nip44,
        )
        .unwrap();
        index.add_entry(entry);
        assert!(index.needs_archiving());
    }

    #[test]
    fn test_file_index_entry_new_valid() {
        let entry = FileIndexEntry::new(
            TEST_HASH.to_string(),
            "test.txt".to_string(),
            1024,
            1234567890,
            EncryptionAlgorithm::Nip44,
        );
        assert!(entry.is_ok());

        let entry = entry.unwrap();
        assert_eq!(entry.file_hash(), TEST_HASH);
        assert_eq!(entry.file_name(), "test.txt");
        assert_eq!(entry.file_size(), 1024);
        assert_eq!(entry.uploaded_at(), 1234567890);
        assert_eq!(entry.encryption(), EncryptionAlgorithm::Nip44);
    }

    #[test]
    fn test_file_index_entry_invalid_hash() {
        // Missing sha256: prefix
        let result = FileIndexEntry::new(
            "abc123".to_string(),
            "test.txt".to_string(),
            1024,
            1234567890,
            EncryptionAlgorithm::Nip44,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("sha256:"));

        // Wrong length
        let result = FileIndexEntry::new(
            "sha256:abc123".to_string(),
            "test.txt".to_string(),
            1024,
            1234567890,
            EncryptionAlgorithm::Nip44,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("64"));
    }

    #[test]
    fn test_file_index_entry_invalid_filename() {
        // Empty filename
        let result = FileIndexEntry::new(
            TEST_HASH.to_string(),
            "".to_string(),
            1024,
            1234567890,
            EncryptionAlgorithm::Nip44,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));

        // Path separator
        let result = FileIndexEntry::new(
            TEST_HASH.to_string(),
            "path/to/file.txt".to_string(),
            1024,
            1234567890,
            EncryptionAlgorithm::Nip44,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("path separator"));

        // Directory traversal ".."
        let result = FileIndexEntry::new(
            TEST_HASH.to_string(),
            "..".to_string(),
            1024,
            1234567890,
            EncryptionAlgorithm::Nip44,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("'..'"));

        // Current directory "."
        let result = FileIndexEntry::new(
            TEST_HASH.to_string(),
            ".".to_string(),
            1024,
            1234567890,
            EncryptionAlgorithm::Nip44,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("'.'"));

        // NUL byte
        let result = FileIndexEntry::new(
            TEST_HASH.to_string(),
            "file\0name.txt".to_string(),
            1024,
            1234567890,
            EncryptionAlgorithm::Nip44,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("NUL"));

        // Control character (tab)
        let result = FileIndexEntry::new(
            TEST_HASH.to_string(),
            "file\tname.txt".to_string(),
            1024,
            1234567890,
            EncryptionAlgorithm::Nip44,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("control"));

        // Control character (newline)
        let result = FileIndexEntry::new(
            TEST_HASH.to_string(),
            "file\nname.txt".to_string(),
            1024,
            1234567890,
            EncryptionAlgorithm::Nip44,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("control"));
    }

    #[test]
    fn test_file_index_entry_invalid_size() {
        let result = FileIndexEntry::new(
            TEST_HASH.to_string(),
            "test.txt".to_string(),
            0,
            1234567890,
            EncryptionAlgorithm::Nip44,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("file_size"));
    }

    #[test]
    fn test_file_index_entry_invalid_timestamp() {
        let result = FileIndexEntry::new(
            TEST_HASH.to_string(),
            "test.txt".to_string(),
            1024,
            0,
            EncryptionAlgorithm::Nip44,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("uploaded_at"));
    }

    #[test]
    fn test_file_index_add_entry() {
        let mut index = FileIndex::new();

        let entry = FileIndexEntry::new(
            TEST_HASH.to_string(),
            "test.txt".to_string(),
            1024,
            1234567890,
            EncryptionAlgorithm::Nip44,
        )
        .unwrap();

        index.add_entry(entry);
        assert_eq!(index.len(), 1);
    }

    #[test]
    fn test_file_index_no_duplicates() {
        let mut index = FileIndex::new();

        let entry1 = FileIndexEntry::new(
            TEST_HASH.to_string(),
            "test.txt".to_string(),
            1024,
            1234567890,
            EncryptionAlgorithm::Nip44,
        )
        .unwrap();

        let entry2 = FileIndexEntry::new(
            TEST_HASH.to_string(),
            "test_updated.txt".to_string(),
            2048,
            1234567900,
            EncryptionAlgorithm::None,
        )
        .unwrap();

        index.add_entry(entry1);
        index.add_entry(entry2);

        assert_eq!(index.len(), 1);
        assert_eq!(index.entries()[0].file_name(), "test_updated.txt");
    }
}
