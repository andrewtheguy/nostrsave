use base64::Engine;
use nostr_sdk::prelude::*;

use crate::config::CHUNK_EVENT_KIND;

/// Data extracted from a chunk event
#[derive(Debug)]
pub struct ChunkEventData {
    pub index: usize,
    pub data: Vec<u8>,
}

/// Create a Nostr event for a file chunk
pub fn create_chunk_event(
    file_hash: &str,
    chunk_index: usize,
    total_chunks: usize,
    chunk_hash: &str,
    chunk_data: &[u8],
    filename: &str,
) -> EventBuilder {
    let d_tag = format!("{}:{}", file_hash, chunk_index);
    let encoded_data = base64::engine::general_purpose::STANDARD.encode(chunk_data);

    EventBuilder::new(Kind::Custom(CHUNK_EVENT_KIND), encoded_data)
        .tag(Tag::identifier(d_tag))
        .tag(Tag::custom(
            TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::X)),
            vec![file_hash.to_string()],
        ))
        .tag(Tag::custom(
            TagKind::custom("chunk"),
            vec![chunk_index.to_string(), total_chunks.to_string()],
        ))
        .tag(Tag::custom(
            TagKind::custom("hash"),
            vec![chunk_hash.to_string()],
        ))
        .tag(Tag::custom(
            TagKind::custom("filename"),
            vec![filename.to_string()],
        ))
        .tag(Tag::custom(
            TagKind::custom("size"),
            vec![chunk_data.len().to_string()],
        ))
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

/// Parse a chunk event to extract chunk data
pub fn parse_chunk_event(event: &Event) -> anyhow::Result<ChunkEventData> {
    // Find chunk tag to get index and total
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

    // Decode base64 content
    let data = base64::engine::general_purpose::STANDARD.decode(event.content.as_bytes())?;

    Ok(ChunkEventData { index, data })
}
