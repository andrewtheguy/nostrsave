use nostr_sdk::prelude::*;
use std::collections::HashSet;

use crate::config::{EncryptionAlgorithm, CHUNK_EVENT_KIND, MANIFEST_EVENT_KIND};
use crate::crypto;
use crate::manifest::Manifest;
use crate::nostr::codec::{
    base85_decode_json_safe, base85_encode_json_safe, zstd_compress, zstd_decompress,
};

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
/// - content: pre-processed content (base85-wrapped NIP-44 string, or base85+zstd payload)
/// - metadata: chunk metadata including encryption mode
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

/// Default maximum identifiers per filter to avoid exceeding relay limits
const DEFAULT_MAX_IDS_PER_FILTER: usize = 100;

/// Create filters to fetch specific chunks by their indices
///
/// Uses `d` tag identifiers (`{file_hash}:{chunk_index}`) for targeted queries.
/// More efficient than fetching all chunks when only a few are missing.
///
/// Indices are deduplicated (preserving order) and split into batches to avoid
/// exceeding relay filter limits. Each batch produces one filter.
///
/// # Arguments
/// * `file_hash` - The file hash to query chunks for
/// * `indices` - Chunk indices to fetch (duplicates are removed)
/// * `pubkey` - Optional author public key to filter by
///
/// # Returns
/// * `Ok(Vec<Filter>)` - One or more filters, each with up to 100 identifiers
/// * `Err` - If `indices` is empty (would create an unconstrained filter)
///
/// # Example
/// ```ignore
/// let filters = create_chunk_filter_for_indices("abc", &[0, 5, 10], Some(&pk))?;
/// for filter in filters {
///     let events = client.fetch_events(filter, timeout).await?;
///     // process events...
/// }
/// ```
pub fn create_chunk_filter_for_indices(
    file_hash: &str,
    indices: &[usize],
    pubkey: Option<&PublicKey>,
) -> anyhow::Result<Vec<Filter>> {
    if file_hash.trim().is_empty() {
        return Err(anyhow::anyhow!("file_hash cannot be empty"));
    }
    if indices.is_empty() {
        return Err(anyhow::anyhow!("indices cannot be empty"));
    }

    // Deduplicate indices while preserving order
    let mut seen = HashSet::new();
    let unique_indices: Vec<usize> = indices
        .iter()
        .filter(|i| seen.insert(**i))
        .copied()
        .collect();

    // Build identifiers
    let identifiers: Vec<String> = unique_indices
        .iter()
        .map(|i| format!("{}:{}", file_hash, i))
        .collect();

    // Split into batches and create filters
    let filters: Vec<Filter> = identifiers
        .chunks(DEFAULT_MAX_IDS_PER_FILTER)
        .map(|batch| {
            let mut filter = Filter::new()
                .kind(Kind::Custom(CHUNK_EVENT_KIND))
                .identifiers(batch.to_vec());

            if let Some(pk) = pubkey {
                filter = filter.author(*pk);
            }

            filter
        })
        .collect();

    Ok(filters)
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
            let encrypted_bytes = base85_decode_json_safe(&event.content)?;
            let encrypted = String::from_utf8(encrypted_bytes)
                .map_err(|e| anyhow::anyhow!("Invalid encrypted payload encoding: {}", e))?;
            let compressed = crypto::decrypt_chunk(keys, &encrypted)?;
            zstd_decompress(&compressed)?
        }
        EncryptionAlgorithm::Aes256Gcm => {
            // Need keys to decrypt
            let keys = keys.ok_or_else(|| {
                anyhow::anyhow!("Chunk is encrypted but no keys provided for decryption")
            })?;
            let encrypted_bytes = base85_decode_json_safe(&event.content)?;
            let compressed = crypto::decrypt_aes256_gcm(keys.secret_key(), &encrypted_bytes)?;
            zstd_decompress(&compressed)?
        }
        EncryptionAlgorithm::None => {
            let compressed = base85_decode_json_safe(&event.content)?;
            zstd_decompress(&compressed)?
        }
    };

    Ok(ChunkEventData { index, data })
}

/// Create a Nostr event for a file manifest
pub fn create_manifest_event(manifest: &Manifest) -> anyhow::Result<EventBuilder> {
    let json = serde_json::to_vec(manifest)?;
    let compressed = zstd_compress(&json)?;
    let content = base85_encode_json_safe(&compressed);

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

    let compressed = base85_decode_json_safe(&event.content)?;
    let json = zstd_decompress(&compressed)?;
    let manifest: Manifest = serde_json::from_slice(&json)?;

    if manifest.version != CURRENT_MANIFEST_VERSION {
        return Err(anyhow::anyhow!(
            "Unsupported manifest version: expected {}, got {}",
            CURRENT_MANIFEST_VERSION,
            manifest.version
        ));
    }

    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr::codec::{base85_encode_json_safe, zstd_compress};
    use sha2::Digest;

    fn assert_json_string_no_escapes(s: &str) {
        let json = serde_json::to_string(s).unwrap();
        assert_eq!(json, format!("\"{}\"", s));
    }

    #[tokio::test]
    async fn test_chunk_event_roundtrip_plain_base85_zstd() {
        let keys = Keys::generate();
        let file_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let data: Vec<u8> = (0..10_000).map(|i| (i % 251) as u8).collect();
        let chunk_hash = hex::encode(sha2::Sha256::digest(&data));

        let compressed = zstd_compress(&data).unwrap();
        let content = base85_encode_json_safe(&compressed);
        assert_json_string_no_escapes(&content);

        let metadata = ChunkMetadata {
            file_hash,
            chunk_index: 0,
            total_chunks: 1,
            chunk_hash: &chunk_hash,
            chunk_data: &data,
            filename: "test.bin",
            encryption: EncryptionAlgorithm::None,
        };

        let event = create_chunk_event(&metadata, &content)
            .unwrap()
            .sign(&keys)
            .await
            .unwrap();

        let parsed = parse_chunk_event(&event, None).unwrap();
        assert_eq!(0, parsed.index);
        assert_eq!(data, parsed.data);
    }

    #[tokio::test]
    async fn test_chunk_event_roundtrip_plain_base85_zstd_minimal() {
        let keys = Keys::generate();
        let file_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let data = vec![0xABu8];
        let chunk_hash = hex::encode(sha2::Sha256::digest(&data));

        let compressed = zstd_compress(&data).unwrap();
        let content = base85_encode_json_safe(&compressed);
        assert_json_string_no_escapes(&content);

        let metadata = ChunkMetadata {
            file_hash,
            chunk_index: 0,
            total_chunks: 1,
            chunk_hash: &chunk_hash,
            chunk_data: &data,
            filename: "test.bin",
            encryption: EncryptionAlgorithm::None,
        };

        let event = create_chunk_event(&metadata, &content)
            .unwrap()
            .sign(&keys)
            .await
            .unwrap();

        let parsed = parse_chunk_event(&event, None).unwrap();
        assert_eq!(0, parsed.index);
        assert_eq!(data, parsed.data);
    }

    #[test]
    fn test_manifest_event_roundtrip_base85_zstd() {
        let manifest = Manifest::new(
            "file.txt".to_string(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            1234,
            1024,
            "npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".to_string(),
            vec!["wss://relay.example.com".to_string()],
            EncryptionAlgorithm::Aes256Gcm,
        )
        .unwrap();

        let keys = Keys::generate();
        let event = create_manifest_event(&manifest)
            .unwrap()
            .sign_with_keys(&keys)
            .unwrap();
        let parsed = parse_manifest_event(&event).unwrap();
        assert_eq!(parsed.file_hash, manifest.file_hash);
        assert_eq!(parsed.file_name, manifest.file_name);
        assert_eq!(parsed.file_size, manifest.file_size);
        assert_eq!(parsed.chunk_size, manifest.chunk_size);
        assert_eq!(parsed.total_chunks, manifest.total_chunks);
        assert_eq!(parsed.pubkey, manifest.pubkey);
        assert_eq!(parsed.encryption, manifest.encryption);
        assert_eq!(parsed.relays, manifest.relays);
    }

    #[tokio::test]
    async fn test_chunk_event_roundtrip_nip44_base85_zstd() {
        let keys = Keys::generate();
        let file_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let data: Vec<u8> = (0..20_000).map(|i| (i % 256) as u8).collect();
        let chunk_hash = hex::encode(sha2::Sha256::digest(&data));

        // Upload format: zstd -> nip44 -> base85-wrap encrypted string bytes
        let compressed = zstd_compress(&data).unwrap();
        let encrypted = crypto::encrypt_chunk(&keys, &compressed).unwrap();
        let content = base85_encode_json_safe(encrypted.as_bytes());
        assert_json_string_no_escapes(&content);

        let metadata = ChunkMetadata {
            file_hash,
            chunk_index: 0,
            total_chunks: 1,
            chunk_hash: &chunk_hash,
            chunk_data: &data,
            filename: "test.bin",
            encryption: EncryptionAlgorithm::Nip44,
        };

        let event = create_chunk_event(&metadata, &content)
            .unwrap()
            .sign(&keys)
            .await
            .unwrap();

        let parsed = parse_chunk_event(&event, Some(&keys)).unwrap();
        assert_eq!(0, parsed.index);
        assert_eq!(data, parsed.data);
    }

    #[tokio::test]
    async fn test_chunk_event_roundtrip_aes256_base85_zstd() {
        let keys = Keys::generate();
        let file_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let data: Vec<u8> = (0..20_000).map(|i| (i % 256) as u8).collect();
        let chunk_hash = hex::encode(sha2::Sha256::digest(&data));

        // Upload format: zstd -> aes256 -> base85-wrap bytes
        let compressed = zstd_compress(&data).unwrap();
        let encrypted = crypto::encrypt_aes256_gcm(keys.secret_key(), &compressed).unwrap();
        let content = base85_encode_json_safe(&encrypted);
        assert_json_string_no_escapes(&content);

        let metadata = ChunkMetadata {
            file_hash,
            chunk_index: 0,
            total_chunks: 1,
            chunk_hash: &chunk_hash,
            chunk_data: &data,
            filename: "test.bin",
            encryption: EncryptionAlgorithm::Aes256Gcm,
        };

        let event = create_chunk_event(&metadata, &content)
            .unwrap()
            .sign(&keys)
            .await
            .unwrap();

        let parsed = parse_chunk_event(&event, Some(&keys)).unwrap();
        assert_eq!(0, parsed.index);
        assert_eq!(data, parsed.data);
    }

    #[tokio::test]
    async fn test_chunk_event_aes256_missing_keys() {
        let keys = Keys::generate();
        let file_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let data: Vec<u8> = (0..1_000).map(|i| (i % 256) as u8).collect();
        let chunk_hash = hex::encode(sha2::Sha256::digest(&data));

        let compressed = zstd_compress(&data).unwrap();
        let encrypted = crypto::encrypt_aes256_gcm(keys.secret_key(), &compressed).unwrap();
        let content = base85_encode_json_safe(&encrypted);

        let metadata = ChunkMetadata {
            file_hash,
            chunk_index: 0,
            total_chunks: 1,
            chunk_hash: &chunk_hash,
            chunk_data: &data,
            filename: "test.bin",
            encryption: EncryptionAlgorithm::Aes256Gcm,
        };

        let event = create_chunk_event(&metadata, &content)
            .unwrap()
            .sign(&keys)
            .await
            .unwrap();

        let result = parse_chunk_event(&event, None);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("no keys provided"),
            "Expected 'no keys provided' error, got: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn test_chunk_event_aes256_wrong_keys() {
        let keys = Keys::generate();
        let wrong_keys = Keys::generate();
        let file_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let data: Vec<u8> = (0..1_000).map(|i| (i % 256) as u8).collect();
        let chunk_hash = hex::encode(sha2::Sha256::digest(&data));

        let compressed = zstd_compress(&data).unwrap();
        let encrypted = crypto::encrypt_aes256_gcm(keys.secret_key(), &compressed).unwrap();
        let content = base85_encode_json_safe(&encrypted);

        let metadata = ChunkMetadata {
            file_hash,
            chunk_index: 0,
            total_chunks: 1,
            chunk_hash: &chunk_hash,
            chunk_data: &data,
            filename: "test.bin",
            encryption: EncryptionAlgorithm::Aes256Gcm,
        };

        let event = create_chunk_event(&metadata, &content)
            .unwrap()
            .sign(&keys)
            .await
            .unwrap();

        let result = parse_chunk_event(&event, Some(&wrong_keys));
        assert!(
            result.is_err(),
            "Decryption with wrong keys should fail"
        );
    }
}
