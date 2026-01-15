use crate::config::EncryptionAlgorithm;
use crate::config::validate_relay_url;
use nostr_sdk::EventId;

const SHA256_HEX_LEN: usize = 64;
const MIN_CHUNK_SIZE: usize = 1024;
const MAX_CHUNK_SIZE: usize = 65408;

/// Parse encryption algorithm from string
pub fn parse_encryption(s: &str) -> Result<EncryptionAlgorithm, String> {
    s.parse::<EncryptionAlgorithm>()
}

/// Parse and validate chunk size within allowed bounds
pub fn parse_chunk_size(s: &str) -> Result<usize, String> {
    let value: usize = s.parse().map_err(|_| format!("'{}' is not a valid number", s))?;

    if value < MIN_CHUNK_SIZE {
        return Err(format!(
            "chunk size must be at least {} bytes (1 KB), got {}",
            MIN_CHUNK_SIZE, value
        ));
    }
    if value > MAX_CHUNK_SIZE {
        return Err(format!(
            "chunk size must be at most {} bytes, got {}",
            MAX_CHUNK_SIZE, value
        ));
    }

    Ok(value)
}

/// Parse and validate file hash (sha256:<hash> or raw 64-hex)
pub fn parse_file_hash(s: &str) -> Result<String, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("hash cannot be empty".to_string());
    }

    let raw = if trimmed.len() >= 7 && trimmed[..7].eq_ignore_ascii_case("sha256:") {
        &trimmed[7..]
    } else {
        trimmed
    };

    if raw.len() != SHA256_HEX_LEN {
        return Err(format!(
            "hash must be {} hex characters, got {}",
            SHA256_HEX_LEN,
            raw.len()
        ));
    }
    if !raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("hash must be hex characters".to_string());
    }

    Ok(raw.to_ascii_lowercase())
}

/// Parse and validate event id (hex, bech32, or NIP-21)
pub fn parse_event_id(s: &str) -> Result<EventId, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("event id cannot be empty".to_string());
    }
    EventId::parse(trimmed)
        .map_err(|e| format!("Invalid event id: {} (expected 64-hex, note1..., or nostr:...)", e))
}

/// Parse and validate a relay URL (wss:// or ws://)
pub fn parse_relay_url(s: &str) -> Result<String, String> {
    validate_relay_url(s).map_err(|e| format!("Invalid relay URL: {e}"))
}

#[cfg(test)]
mod tests {
    use super::{
        parse_chunk_size, parse_encryption, parse_event_id, parse_file_hash, parse_relay_url,
    };
    use crate::config::EncryptionAlgorithm;
    use nostr_sdk::{EventId, ToBech32};

    #[test]
    fn test_parse_event_id_accepts_hex() {
        let input = "0000000000000000000000000000000000000000000000000000000000000001";
        let parsed = parse_event_id(input).unwrap();
        assert_eq!(parsed, EventId::from_hex(input).unwrap());
    }

    #[test]
    fn test_parse_event_id_rejects_wrong_length() {
        assert!(parse_event_id("abc123").is_err());
    }

    #[test]
    fn test_parse_event_id_rejects_non_hex() {
        let input = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        assert!(parse_event_id(input).is_err());
    }

    #[test]
    fn test_parse_event_id_accepts_note() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let event_id = EventId::from_hex(hex).unwrap();
        let note = event_id.to_bech32().unwrap();
        assert_eq!(parse_event_id(&note).unwrap(), event_id);
    }

    #[test]
    fn test_parse_file_hash_accepts_raw_hex() {
        let hash = "20d3323a2bcce6f25498b8911a397503a0a99fa92b6ba58d62788cb42b6e5459";
        assert_eq!(parse_file_hash(hash).unwrap(), hash);
    }

    #[test]
    fn test_parse_file_hash_accepts_sha256_prefix() {
        let hash = "20d3323a2bcce6f25498b8911a397503a0a99fa92b6ba58d62788cb42b6e5459";
        let input = format!("sha256:{hash}");
        assert_eq!(parse_file_hash(&input).unwrap(), hash);
    }

    #[test]
    fn test_parse_file_hash_normalizes_case() {
        let input = "SHA256:20D3323A2BCCE6F25498B8911A397503A0A99FA92B6BA58D62788CB42B6E5459";
        let expected = "20d3323a2bcce6f25498b8911a397503a0a99fa92b6ba58d62788cb42b6e5459";
        assert_eq!(parse_file_hash(input).unwrap(), expected);
    }

    #[test]
    fn test_parse_file_hash_rejects_empty() {
        assert!(parse_file_hash(" ").is_err());
    }

    #[test]
    fn test_parse_file_hash_rejects_wrong_length() {
        assert!(parse_file_hash("abc123").is_err());
    }

    #[test]
    fn test_parse_file_hash_rejects_non_hex() {
        let input = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        assert!(parse_file_hash(input).is_err());
    }

    #[test]
    fn test_parse_relay_url_accepts_wss() {
        let input = "wss://relay.nostr.band";
        assert_eq!(parse_relay_url(input).unwrap(), input);
    }

    #[test]
    fn test_parse_relay_url_accepts_ws() {
        let input = "ws://relay.nostr.band";
        assert_eq!(parse_relay_url(input).unwrap(), input);
    }

    #[test]
    fn test_parse_relay_url_rejects_trailing_comma() {
        assert!(parse_relay_url("wss://relay.nostr.band,").is_err());
    }

    #[test]
    fn test_parse_relay_url_rejects_bad_scheme() {
        assert!(parse_relay_url("https://relay.nostr.band").is_err());
        assert!(parse_relay_url("ftp://relay.nostr.band").is_err());
    }

    #[test]
    fn test_parse_relay_url_rejects_missing_host() {
        assert!(parse_relay_url("wss://").is_err());
    }

    #[test]
    fn test_parse_relay_url_rejects_bad_host_labels() {
        assert!(parse_relay_url("wss://relay..nostr.band").is_err());
        assert!(parse_relay_url("wss://-relay.nostr.band").is_err());
        assert!(parse_relay_url("wss://relay-.nostr.band").is_err());
        assert!(parse_relay_url("wss://relay_nostr.band").is_err());
    }

    #[test]
    fn test_parse_relay_url_rejects_userinfo_query_fragment() {
        assert!(parse_relay_url("wss://user:pass@relay.nostr.band").is_err());
        assert!(parse_relay_url("wss://relay.nostr.band?x=1").is_err());
        assert!(parse_relay_url("wss://relay.nostr.band#frag").is_err());
    }

    #[test]
    fn test_parse_relay_url_rejects_port_zero() {
        assert!(parse_relay_url("wss://relay.nostr.band:0").is_err());
    }

    #[test]
    fn test_parse_chunk_size_rejects_small() {
        assert!(parse_chunk_size("1").is_err());
    }

    #[test]
    fn test_parse_chunk_size_rejects_large() {
        assert!(parse_chunk_size("9999999").is_err());
    }

    #[test]
    fn test_parse_chunk_size_accepts_bounds() {
        assert_eq!(parse_chunk_size("1024").unwrap(), 1024);
        assert_eq!(parse_chunk_size("65408").unwrap(), 65408);
    }

    #[test]
    fn test_parse_encryption_accepts_values() {
        assert_eq!(
            parse_encryption("aes256gcm").unwrap(),
            EncryptionAlgorithm::Aes256Gcm
        );
        assert_eq!(
            parse_encryption("nip44").unwrap(),
            EncryptionAlgorithm::Nip44
        );
        assert_eq!(
            parse_encryption("none").unwrap(),
            EncryptionAlgorithm::None
        );
    }
}
