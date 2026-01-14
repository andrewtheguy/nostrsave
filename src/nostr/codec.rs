use std::io::{Cursor, Read, Write};

const ZSTD_COMPRESSION_LEVEL: i32 = 9;
const MAX_DECOMPRESSED_SIZE: u64 = 10 * 1024 * 1024; // 10 MiB

pub fn zstd_compress(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    zstd_compress_with_level(data, ZSTD_COMPRESSION_LEVEL)
}

/// Compress data using zstd at the specified compression level.
///
/// Checksum is intentionally disabled to save 4 bytes per chunk, since data
/// integrity is already provided by AES-GCM authentication tags or Nostr
/// event signatures.
pub fn zstd_compress_with_level(data: &[u8], level: i32) -> anyhow::Result<Vec<u8>> {
    let mut encoder = zstd::stream::Encoder::new(Vec::new(), level)?;
    encoder.include_checksum(false)?;
    encoder.write_all(data)?;
    encoder.finish().map_err(|e| anyhow::anyhow!("zstd compression failed: {}", e))
}

pub fn zstd_decompress(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut decoder = zstd::stream::Decoder::new(Cursor::new(data))
        .map_err(|e| anyhow::anyhow!("zstd decoder init failed: {}", e))?;

    let estimated = (data.len() as u64).saturating_mul(4);
    let min_cap = 4 * 1024u64;
    let cap = estimated.clamp(min_cap, MAX_DECOMPRESSED_SIZE) as usize;
    let mut output = Vec::with_capacity(cap);
    decoder
        .by_ref()
        .take(MAX_DECOMPRESSED_SIZE + 1)
        .read_to_end(&mut output)
        .map_err(|e| anyhow::anyhow!("zstd decompression failed: {}", e))?;

    if output.len() as u64 > MAX_DECOMPRESSED_SIZE {
        return Err(anyhow::anyhow!(
            "decompressed data exceeds size limit ({} bytes)",
            MAX_DECOMPRESSED_SIZE
        ));
    }

    Ok(output)
}

pub fn base85_encode_json_safe(data: &[u8]) -> String {
    // Note: despite being named Z85, the `z85` crate supports arbitrary-length input by
    // emitting a tail chunk when `len % 4 != 0`, so callers don't need to pre-pad.
    z85::encode(data)
}

pub fn base85_decode_json_safe(s: &str) -> anyhow::Result<Vec<u8>> {
    z85::decode(s)
        .map_err(|e| anyhow::anyhow!("base85 decode failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base85_roundtrip_various_lengths() {
        for len in 0..128 {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let encoded = base85_encode_json_safe(&data);
            let decoded = base85_decode_json_safe(&encoded).unwrap();
            assert_eq!(data, decoded);
        }
    }

    #[test]
    fn test_zstd_roundtrip_levels() {
        let data: Vec<u8> = (0..65535).map(|i| (i % 256) as u8).collect();

        for level in [0, 1, 3, 9] {
            let compressed = zstd_compress_with_level(&data, level).unwrap();
            let decompressed = zstd_decompress(&compressed).unwrap();
            assert_eq!(data, decompressed);
        }
    }

    #[test]
    fn test_base85_zstd_pipeline_roundtrip() {
        let data = b"nostrsave test payload: zstd + base85 should roundtrip";
        let compressed = zstd_compress(data).unwrap();
        let encoded = base85_encode_json_safe(&compressed);
        let decoded = base85_decode_json_safe(&encoded).unwrap();
        let decompressed = zstd_decompress(&decoded).unwrap();
        assert_eq!(data.to_vec(), decompressed);
    }

    #[test]
    fn test_zstd_decompress_enforces_size_limit() {
        let data = vec![0u8; (MAX_DECOMPRESSED_SIZE as usize) + 1];
        let compressed = zstd_compress_with_level(&data, 1).unwrap();
        let err = zstd_decompress(&compressed).unwrap_err();
        assert!(err.to_string().contains("exceeds size limit"));
    }

    #[test]
    fn test_zstd_decompress_at_exact_limit() {
        let data = vec![0u8; MAX_DECOMPRESSED_SIZE as usize];
        let compressed = zstd_compress_with_level(&data, 1).unwrap();
        let decompressed = zstd_decompress(&compressed).unwrap();
        assert_eq!(data.len(), decompressed.len());
    }
}
