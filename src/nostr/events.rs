use base64::Engine;
use nostr_sdk::prelude::*;

use crate::config::{EncryptionAlgorithm, CHUNK_EVENT_KIND, MANIFEST_EVENT_KIND};
use crate::crypto;
use crate::manifest::Manifest;

/// Data extracted from a chunk event
#[derive(Debug, Clone)]
pub struct ChunkEventData {
    pub index: usize,
    pub data: Vec<u8>,
}

/// Metadata for creating a chunk event
#[derive(Debug)]
pub struct ChunkMetadata<'a> {
    pub file_hash: &'a str,
    pub chunk_index: usize,
    pub total_chunks: usize,
    pub chunk_hash: &'a str,
    pub chunk_data: &'a [u8],
    pub filename: &'a str,
    pub encryption: EncryptionAlgorithm,
}

/// Create a Nostr event for a file chunk
///
/// - content: pre-processed content (encrypted string or base64-encoded)
/// - metadata: chunk metadata including encrypted flag
pub fn create_chunk_event(metadata: &ChunkMetadata, content: &str) -> anyhow::Result<EventBuilder> {
    // Validate inputs
    if metadata.chunk_index >= metadata.total_chunks {
        return Err(anyhow::anyhow!(
            "chunk_index ({}) must be less than total_chunks ({})",
            metadata.chunk_index,
            metadata.total_chunks
        ));
    }
    if metadata.chunk_data.is_empty() {
        return Err(anyhow::anyhow!("chunk_data cannot be empty"));
    }
    if metadata.file_hash.is_empty() {
        return Err(anyhow::anyhow!("file_hash cannot be empty"));
    }
    if metadata.chunk_hash.is_empty() {
        return Err(anyhow::anyhow!("chunk_hash cannot be empty"));
    }
    if content.is_empty() {
        return Err(anyhow::anyhow!("content cannot be empty"));
    }

    let d_tag = format!("{}:{}", metadata.file_hash, metadata.chunk_index);

    Ok(EventBuilder::new(Kind::Custom(CHUNK_EVENT_KIND), content)
        .tag(Tag::identifier(d_tag))
        .tag(Tag::custom(
            TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::X)),
            vec![metadata.file_hash.to_string()],
        ))
        .tag(Tag::custom(
            TagKind::custom("chunk"),
            vec![metadata.chunk_index.to_string(), metadata.total_chunks.to_string()],
        ))
        .tag(Tag::custom(
            TagKind::custom("hash"),
            vec![metadata.chunk_hash.to_string()],
        ))
        .tag(Tag::custom(
            TagKind::custom("filename"),
            vec![metadata.filename.to_string()],
        ))
        .tag(Tag::custom(
            TagKind::custom("size"),
            vec![metadata.chunk_data.len().to_string()],
        ))
        .tag(Tag::custom(
            TagKind::custom("encryption"),
            vec![metadata.encryption.to_string()],
        )))
}

/// Create a filter to fetch all chunks for a file by its hash
pub fn create_chunk_filter(file_hash: &str, pubkey: Option<&PublicKey>) -> Filter {
    let mut filter = Filter::new()
        .kind(Kind::Custom(CHUNK_EVENT_KIND))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::X), file_hash.to_string());

    if let Some(pk) = pubkey {
        filter = filter.author(*pk);
    }

    filter
}

/// Create a filter to fetch specific chunks by their indices
///
/// Uses `d` tag identifiers (`{file_hash}:{chunk_index}`) for targeted queries.
/// More efficient than fetching all chunks when only a few are missing.
pub fn create_chunk_filter_for_indices(
    file_hash: &str,
    indices: &[usize],
    pubkey: Option<&PublicKey>,
) -> Filter {
    let identifiers: Vec<String> = indices
        .iter()
        .map(|i| format!("{}:{}", file_hash, i))
        .collect();

    let mut filter = Filter::new()
        .kind(Kind::Custom(CHUNK_EVENT_KIND))
        .identifiers(identifiers);

    if let Some(pk) = pubkey {
        filter = filter.author(*pk);
    }

    filter
}

/// Parse a chunk event to extract chunk data
///
/// If keys are provided and the chunk is encrypted, decrypts the content.
pub fn parse_chunk_event(event: &Event, keys: Option<&Keys>) -> anyhow::Result<ChunkEventData> {
    // Find chunk tag to get index
    let chunk_tag = event
        .tags
        .iter()
        .find(|t| t.kind() == TagKind::custom("chunk"))
        .ok_or_else(|| anyhow::anyhow!("Missing chunk tag"))?;

    let tag_vec: Vec<&str> = chunk_tag.as_slice().iter().map(|s| s.as_str()).collect();
    if tag_vec.len() < 3 {
        return Err(anyhow::anyhow!("Invalid chunk tag format"));
    }

    let index: usize = tag_vec[1].parse()?;

    // Check encryption algorithm - fail fast on missing or unknown values
    let encryption_tag = event
        .tags
        .iter()
        .find(|t| t.kind() == TagKind::custom("encryption"))
        .ok_or_else(|| anyhow::anyhow!("Missing encryption tag in chunk event"))?;

    let encryption_value = encryption_tag
        .as_slice()
        .get(1)
        .ok_or_else(|| anyhow::anyhow!("Encryption tag has no value"))?;

    let encryption = encryption_value
        .parse::<EncryptionAlgorithm>()
        .map_err(|e| anyhow::anyhow!("Unsupported encryption algorithm '{}': {}", encryption_value, e))?;

    let data = match encryption {
        EncryptionAlgorithm::Nip44 => {
            // Need keys to decrypt
            let keys = keys.ok_or_else(|| {
                anyhow::anyhow!("Chunk is encrypted but no keys provided for decryption")
            })?;
            crypto::decrypt_chunk(keys, &event.content)?
        }
        EncryptionAlgorithm::None => {
            // Plain base64 decode
            base64::engine::general_purpose::STANDARD.decode(event.content.as_bytes())?
        }
    };

    Ok(ChunkEventData { index, data })
}

/// Create a Nostr event for a file manifest
pub fn create_manifest_event(manifest: &Manifest) -> anyhow::Result<EventBuilder> {
    let content = serde_json::to_string(manifest)?;

    Ok(EventBuilder::new(Kind::Custom(MANIFEST_EVENT_KIND), content)
        .tag(Tag::identifier(manifest.file_hash.clone()))
        .tag(Tag::custom(
            TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::X)),
            vec![manifest.file_hash.clone()],
        ))
        .tag(Tag::custom(
            TagKind::custom("filename"),
            vec![manifest.file_name.clone()],
        ))
        .tag(Tag::custom(
            TagKind::custom("size"),
            vec![manifest.file_size.to_string()],
        )))
}

/// Create a filter to fetch a manifest by file hash
pub fn create_manifest_filter(file_hash: &str) -> Filter {
    Filter::new()
        .kind(Kind::Custom(MANIFEST_EVENT_KIND))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::X), file_hash.to_string())
}

/// Parse a manifest event to extract the manifest
pub fn parse_manifest_event(event: &Event) -> anyhow::Result<Manifest> {
    use crate::manifest::CURRENT_MANIFEST_VERSION;

    let manifest: Manifest = serde_json::from_str(&event.content)?;

    if manifest.version != CURRENT_MANIFEST_VERSION {
        return Err(anyhow::anyhow!(
            "Unsupported manifest version: expected {}, got {}",
            CURRENT_MANIFEST_VERSION,
            manifest.version
        ));
    }

    Ok(manifest)
}
