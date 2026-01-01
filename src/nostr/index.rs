use crate::config::{EncryptionAlgorithm, FILE_INDEX_EVENT_KIND};
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};

/// Identifier for the file index replaceable event
pub const FILE_INDEX_IDENTIFIER: &str = "nostrsave-index";

/// Current file index version
pub const CURRENT_FILE_INDEX_VERSION: u8 = 1;

/// A single entry in the file index
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIndexEntry {
    pub file_hash: String,
    pub file_name: String,
    pub file_size: u64,
    pub uploaded_at: u64,
    pub encryption: EncryptionAlgorithm,
}

/// The file index containing all uploaded files for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIndex {
    pub version: u8,
    pub entries: Vec<FileIndexEntry>,
}

impl FileIndex {
    /// Create a new empty file index
    pub fn new() -> Self {
        Self {
            version: CURRENT_FILE_INDEX_VERSION,
            entries: Vec::new(),
        }
    }

    /// Add an entry, replacing any existing entry with the same file_hash
    pub fn add_entry(&mut self, entry: FileIndexEntry) {
        if let Some(pos) = self.entries.iter().position(|e| e.file_hash == entry.file_hash) {
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
        Tag::identifier(FILE_INDEX_IDENTIFIER),
    ];

    Ok(EventBuilder::new(Kind::Custom(FILE_INDEX_EVENT_KIND), content).tags(tags))
}

/// Create a filter to query for a user's file index
pub fn create_file_index_filter(pubkey: &PublicKey) -> Filter {
    Filter::new()
        .kind(Kind::Custom(FILE_INDEX_EVENT_KIND))
        .author(*pubkey)
        .identifier(FILE_INDEX_IDENTIFIER)
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

    if index.version != CURRENT_FILE_INDEX_VERSION {
        return Err(anyhow::anyhow!(
            "Unsupported file index version: expected {}, got {}",
            CURRENT_FILE_INDEX_VERSION,
            index.version
        ));
    }

    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_index_new() {
        let index = FileIndex::new();
        assert_eq!(index.version, CURRENT_FILE_INDEX_VERSION);
        assert!(index.is_empty());
    }

    #[test]
    fn test_file_index_add_entry() {
        let mut index = FileIndex::new();

        let entry = FileIndexEntry {
            file_hash: "sha256:abc123".to_string(),
            file_name: "test.txt".to_string(),
            file_size: 1024,
            uploaded_at: 1234567890,
            encryption: EncryptionAlgorithm::Nip44,
        };

        index.add_entry(entry);
        assert_eq!(index.len(), 1);
    }

    #[test]
    fn test_file_index_no_duplicates() {
        let mut index = FileIndex::new();

        let entry1 = FileIndexEntry {
            file_hash: "sha256:abc123".to_string(),
            file_name: "test.txt".to_string(),
            file_size: 1024,
            uploaded_at: 1234567890,
            encryption: EncryptionAlgorithm::Nip44,
        };

        let entry2 = FileIndexEntry {
            file_hash: "sha256:abc123".to_string(),
            file_name: "test_updated.txt".to_string(),
            file_size: 2048,
            uploaded_at: 1234567900,
            encryption: EncryptionAlgorithm::None,
        };

        index.add_entry(entry1);
        index.add_entry(entry2.clone());

        assert_eq!(index.len(), 1);
        assert_eq!(index.entries[0].file_name, "test_updated.txt");
    }
}
