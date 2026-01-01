//! NIP-44 encryption utilities for chunk data

use nostr_sdk::prelude::*;

/// Encrypt chunk data using NIP-44 (self-encryption to own public key)
///
/// Returns base64-encoded encrypted string
pub fn encrypt_chunk(keys: &Keys, chunk_data: &[u8]) -> anyhow::Result<String> {
    let encrypted = nip44::encrypt(
        keys.secret_key(),
        &keys.public_key(),
        chunk_data,
        nip44::Version::V2,
    )
    .map_err(|e| anyhow::anyhow!("NIP-44 encryption failed: {}", e))?;

    Ok(encrypted)
}

/// Decrypt chunk data using NIP-44
///
/// Takes base64-encoded encrypted string, returns raw bytes
pub fn decrypt_chunk(keys: &Keys, encrypted_content: &str) -> anyhow::Result<Vec<u8>> {
    let decrypted = nip44::decrypt_to_bytes(
        keys.secret_key(),
        &keys.public_key(),
        encrypted_content,
    )
    .map_err(|e| anyhow::anyhow!("NIP-44 decryption failed: {}", e))?;

    Ok(decrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let keys = Keys::generate();
        let original_data = b"Hello, World! This is test chunk data.";

        let encrypted = encrypt_chunk(&keys, original_data).unwrap();
        let decrypted = decrypt_chunk(&keys, &encrypted).unwrap();

        assert_eq!(original_data.to_vec(), decrypted);
    }

    #[test]
    fn test_encrypt_produces_different_output() {
        let keys = Keys::generate();
        let data = b"test data";

        let encrypted1 = encrypt_chunk(&keys, data).unwrap();
        let encrypted2 = encrypt_chunk(&keys, data).unwrap();

        // NIP-44 uses random nonces, so encryptions should differ
        assert_ne!(encrypted1, encrypted2);
    }
}
