//! NIP-44 encryption utilities for chunk data

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use ::hkdf::Hkdf;
use nostr_sdk::prelude::*;
use sha2::Sha256;

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

/// Derive AES-256 key from Nostr secret key using HKDF-SHA256
fn derive_aes_key(secret_key: &SecretKey) -> Key<Aes256Gcm> {
    let ikm = secret_key.to_secret_bytes();
    let hkdf = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    // Info string ensures domain separation for this specific usage
    hkdf.expand(b"nostrsave-file-encryption-v1", &mut okm)
        .expect("HKDF expansion should not fail for correct length");
    *Key::<Aes256Gcm>::from_slice(&okm)
}

/// Encrypt data using AES-256-GCM with key derived from Nostr private key
///
/// Output format: [nonce (12 bytes)] + [ciphertext] + [tag (16 bytes included in ciphertext)]
pub fn encrypt_aes256_gcm(secret_key: &SecretKey, data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let key = derive_aes_key(secret_key);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message

    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|e| anyhow::anyhow!("AES encryption failed: {}", e))?;

    let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt data using AES-256-GCM with key derived from Nostr private key
pub fn decrypt_aes256_gcm(secret_key: &SecretKey, data: &[u8]) -> anyhow::Result<Vec<u8>> {
    if data.len() < 12 {
        return Err(anyhow::anyhow!("Invalid encrypted data: too short for nonce"));
    }

    let key = derive_aes_key(secret_key);
    let cipher = Aes256Gcm::new(&key);
    
    let nonce = Nonce::from_slice(&data[0..12]);
    let ciphertext = &data[12..];

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("AES decryption failed: {}", e))?;

    Ok(plaintext)
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

    #[test]
    fn test_aes256_roundtrip() {
        let keys = Keys::generate();
        let original_data = b"Hello, AES World! This is secured with AES-256-GCM.";

        let encrypted = encrypt_aes256_gcm(keys.secret_key(), original_data).unwrap();
        // Check structure: Nonce (12) + Ciphertext
        assert!(encrypted.len() > 12 + original_data.len()); // GCM adds overhead (tag)

        let decrypted = decrypt_aes256_gcm(keys.secret_key(), &encrypted).unwrap();
        assert_eq!(original_data.to_vec(), decrypted);
    }

    #[test]
    fn test_aes256_random_nonce() {
        let keys = Keys::generate();
        let data = b"same data";

        let encrypted1 = encrypt_aes256_gcm(keys.secret_key(), data).unwrap();
        let encrypted2 = encrypt_aes256_gcm(keys.secret_key(), data).unwrap();

        assert_ne!(encrypted1, encrypted2);
        // Nonces are at the start
        assert_ne!(&encrypted1[0..12], &encrypted2[0..12]);
    }

    #[test]
    fn test_aes256_wrong_key() {
        let keys1 = Keys::generate();
        let keys2 = Keys::generate();
        let data = b"top secret";

        let encrypted = encrypt_aes256_gcm(keys1.secret_key(), data).unwrap();
        let result = decrypt_aes256_gcm(keys2.secret_key(), &encrypted);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_nip44_max_size() {
        let keys = Keys::generate();

        // Binary search to find exact limit
        let mut low = 65000;
        let mut high = 65535;
        let mut max_working = low;

        while low <= high {
            let mid = (low + high) / 2;
            let data: Vec<u8> = (0..mid).map(|i| (i % 256) as u8).collect();
            if encrypt_chunk(&keys, &data).is_ok() {
                max_working = mid;
                low = mid + 1;
            } else {
                high = mid - 1;
            }
        }

        println!("Maximum working NIP-44 plaintext size: {}", max_working);

        // Verify max_working works
        let data: Vec<u8> = (0..max_working).map(|i| (i % 256) as u8).collect();
        let encrypted = encrypt_chunk(&keys, &data).unwrap();
        println!("Encrypted len at max size: {}", encrypted.len());
        let decrypted = decrypt_chunk(&keys, &encrypted).unwrap();
        assert_eq!(data, decrypted);

        // Verify max_working + 1 fails
        let data: Vec<u8> = (0..=max_working).map(|i| (i % 256) as u8).collect();
        assert!(encrypt_chunk(&keys, &data).is_err());
    }
}
