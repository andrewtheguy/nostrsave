use std::io::Cursor;

const ZSTD_COMPRESSION_LEVEL: i32 = 3;

pub fn zstd_compress(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    zstd::stream::encode_all(Cursor::new(data), ZSTD_COMPRESSION_LEVEL)
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

