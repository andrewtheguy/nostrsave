use std::io::Cursor;

const ZSTD_COMPRESSION_LEVEL: i32 = 9;

pub fn zstd_compress(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    zstd_compress_with_level(data, ZSTD_COMPRESSION_LEVEL)
}

pub fn zstd_compress_with_level(data: &[u8], level: i32) -> anyhow::Result<Vec<u8>> {
    zstd::stream::encode_all(Cursor::new(data), level)
        .map_err(|e| anyhow::anyhow!("zstd compression failed: {}", e))
}

pub fn zstd_decompress(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    zstd::stream::decode_all(Cursor::new(data))
        .map_err(|e| anyhow::anyhow!("zstd decompression failed: {}", e))
}

pub fn base85_encode_json_safe(data: &[u8]) -> String {
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
}
