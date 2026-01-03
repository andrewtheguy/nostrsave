use crate::config::EncryptionAlgorithm;
use crate::crypto;
use crate::nostr::{create_chunk_event, create_chunk_filter, ChunkMetadata};
use futures::stream::{self, StreamExt};
use nostr_sdk::prelude::*;
use rand::Rng;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

/// Result of testing a single relay
#[derive(Debug, Clone, Serialize)]
pub struct RelayTestResult {
    pub url: String,
    pub connected: bool,
    pub latency_ms: Option<u64>,
    pub can_write: bool,
    pub can_read: bool,
    pub round_trip_ms: Option<u64>,
    pub payload_size: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl RelayTestResult {
    /// Check if the relay is considered working for file storage
    pub fn is_working(&self) -> bool {
        self.connected && self.can_write && self.can_read
    }
}

/// Discover relays from the nostr.watch API
pub async fn discover_relays_from_nostr_watch() -> anyhow::Result<Vec<String>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let response = client
        .get("https://api.nostr.watch/v1/online")
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "nostr.watch API returned status {}",
            response.status()
        ));
    }

    let relays: Vec<String> = response.json().await?;
    Ok(relays)
}

/// Test a single relay for connectivity and round-trip with chunk-sized payload.
/// This is used by the `discover-relays` command to validate relays for this app's
/// file-chunk use case (not an integration test harness).
pub async fn test_relay(url: &str, timeout: Duration, chunk_size: usize) -> RelayTestResult {
    let start = Instant::now();

    // Create a temporary keypair for testing
    let keys = Keys::generate();
    let client = Client::new(keys.clone());

    let base_result = RelayTestResult {
        url: url.to_string(),
        connected: false,
        latency_ms: None,
        can_write: false,
        can_read: false,
        round_trip_ms: None,
        payload_size: chunk_size,
        error: None,
    };

    // Try to add the relay
    if let Err(e) = client.add_relay(url).await {
        return RelayTestResult {
            error: Some(format!("Failed to add relay: {}", e)),
            ..base_result
        };
    }

    // Connect with timeout
    client.connect().await;
    client.wait_for_connection(timeout).await;

    // Check if connection was established
    let connected = client
        .relays()
        .await
        .into_iter()
        .next()
        .is_some_and(|(_, relay)| relay.is_connected());

    if !connected {
        client.disconnect().await;
        return RelayTestResult {
            latency_ms: Some(start.elapsed().as_millis() as u64),
            error: Some("Connection timeout".to_string()),
            ..base_result
        };
    }

    let connect_latency = start.elapsed().as_millis() as u64;

    // Generate test payload with random data
    let mut test_data = vec![0u8; chunk_size];
    rand::thread_rng().fill(&mut test_data[..]);
    let test_hash = format!("sha256:{}", hex::encode(Sha256::digest(&test_data)));

    // Encrypt test data using NIP-44 (same as actual upload)
    let encrypted_content = match crypto::encrypt_chunk(&keys, &test_data) {
        Ok(content) => content,
        Err(e) => {
            client.disconnect().await;
            return RelayTestResult {
                connected: true,
                latency_ms: Some(connect_latency),
                payload_size: chunk_size,
                error: Some(format!("NIP-44 encryption failed: {}", e)),
                ..base_result
            };
        }
    };

    // Create a test chunk event with the same structure as production uploads
    let filename_suffix: u32 = rand::thread_rng().gen();
    let filename = format!("nostrsave-relay-test-{:08x}", filename_suffix);
    let metadata = ChunkMetadata {
        file_hash: &test_hash,
        chunk_index: 0,
        total_chunks: 1,
        chunk_hash: &test_hash,
        chunk_data: &test_data,
        filename: &filename,
        encryption: EncryptionAlgorithm::Nip44,
    };
    let builder = match create_chunk_event(&metadata, &encrypted_content) {
        Ok(builder) => builder,
        Err(e) => {
            client.disconnect().await;
            return RelayTestResult {
                connected: true,
                latency_ms: Some(connect_latency),
                payload_size: chunk_size,
                error: Some(format!("Failed to build chunk event: {}", e)),
                ..base_result
            };
        }
    };

    let round_trip_start = Instant::now();

    // Publish test event with NIP-44 encrypted payload
    let can_write = match tokio::time::timeout(timeout, async {
        client.send_event_builder(builder).await
    })
    .await
    {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            client.disconnect().await;
            return RelayTestResult {
                connected: true,
                latency_ms: Some(connect_latency),
                payload_size: chunk_size,
                error: Some(format!("Write failed: {}", e)),
                ..base_result
            };
        }
        Err(_) => {
            client.disconnect().await;
            return RelayTestResult {
                connected: true,
                latency_ms: Some(connect_latency),
                payload_size: chunk_size,
                error: Some("Write timeout".to_string()),
                ..base_result
            };
        }
    };

    // Small delay to allow relay to process
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Fetch the test event back
    let filter = create_chunk_filter(&test_hash, Some(&keys.public_key())).limit(1);

    let (can_read, error) = match client.fetch_events(filter, timeout).await {
        Ok(events) => {
            if let Some(event) = events.iter().next() {
                // Decrypt and verify the content matches original data
                match crypto::decrypt_chunk(&keys, &event.content) {
                    Ok(decrypted) => {
                        if decrypted == test_data {
                            (true, None)
                        } else {
                            (false, Some("Content mismatch after decryption".to_string()))
                        }
                    }
                    Err(e) => (false, Some(format!("Decryption failed: {}", e))),
                }
            } else {
                (false, Some("Event not found on read".to_string()))
            }
        }
        Err(e) => (false, Some(format!("Read failed: {}", e))),
    };

    let round_trip_ms = round_trip_start.elapsed().as_millis() as u64;

    client.disconnect().await;

    RelayTestResult {
        url: url.to_string(),
        connected: true,
        latency_ms: Some(connect_latency),
        can_write,
        can_read,
        round_trip_ms: Some(round_trip_ms),
        payload_size: chunk_size,
        error,
    }
}


/// Test multiple relays concurrently with chunk-sized payload
pub async fn test_relays_concurrent(
    urls: Vec<String>,
    concurrency: usize,
    timeout: Duration,
    chunk_size: usize,
    progress_callback: Option<Box<dyn Fn(usize, usize) + Send + Sync>>,
) -> Vec<RelayTestResult> {
    let total = urls.len();
    let completed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let callback = progress_callback.map(std::sync::Arc::new);

    let results: Vec<RelayTestResult> = stream::iter(urls)
        .map(|url| {
            let completed = completed.clone();
            let callback = callback.clone();
            async move {
                let result = test_relay(&url, timeout, chunk_size).await;

                let done = completed.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                if let Some(ref cb) = callback {
                    cb(done, total);
                }

                result
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    results
}

/// Discover relays from NIP-65 relay list metadata events (kind 10002)
/// Connects to the provided relays and fetches kind 10002 events,
/// then extracts relay URLs from the "r" tags.
pub async fn discover_relays_from_nip65(
    index_relays: &[String],
    timeout: Duration,
) -> anyhow::Result<Vec<String>> {
    use std::collections::HashSet;

    // Create a temporary client for querying
    let keys = Keys::generate();
    let client = Client::new(keys);

    // Add relays
    for relay in index_relays {
        if let Err(e) = client.add_relay(relay).await {
            eprintln!("  Warning: Failed to add relay {}: {}", relay, e);
        }
    }

    // Connect
    client.connect().await;
    client.wait_for_connection(timeout).await;

    // Verify at least one relay connected
    let connected_count = client
        .relays()
        .await
        .into_iter()
        .filter(|(_, r)| r.is_connected())
        .count();

    if connected_count == 0 {
        client.disconnect().await;
        return Err(anyhow::anyhow!("No index relays connected"));
    }

    // Create filter for NIP-65 relay list events (kind 10002)
    let filter = Filter::new().kind(Kind::RelayList).limit(500);

    // Fetch events
    let events = match client.fetch_events(filter, timeout).await {
        Ok(events) => events,
        Err(e) => {
            client.disconnect().await;
            return Err(anyhow::anyhow!("Failed to fetch NIP-65 events: {}", e));
        }
    };

    client.disconnect().await;

    // Extract relay URLs from "r" tags
    let mut relays: HashSet<String> = HashSet::new();

    for event in events.iter() {
        for tag in event.tags.iter() {
            // NIP-65 uses single-letter "r" tags: ["r", "wss://relay.url", optional "read"|"write"]
            let is_relay_tag = tag
                .single_letter_tag()
                .map(|slt| slt.character == Alphabet::R)
                .unwrap_or(false);

            if is_relay_tag {
                if let Some(relay_url) = tag.content() {
                    // Basic validation: must start with ws:// or wss://
                    if relay_url.starts_with("wss://") || relay_url.starts_with("ws://") {
                        relays.insert(relay_url.to_string());
                    }
                }
            }
        }
    }

    Ok(relays.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_result_is_working() {
        let working = RelayTestResult {
            url: "wss://test.relay".to_string(),
            connected: true,
            latency_ms: Some(100),
            can_write: true,
            can_read: true,
            round_trip_ms: Some(500),
            payload_size: 32768,
            error: None,
        };
        assert!(working.is_working());

        let not_connected = RelayTestResult {
            url: "wss://test.relay".to_string(),
            connected: false,
            latency_ms: None,
            can_write: false,
            can_read: false,
            round_trip_ms: None,
            payload_size: 32768,
            error: Some("timeout".to_string()),
        };
        assert!(!not_connected.is_working());

        let no_read = RelayTestResult {
            url: "wss://test.relay".to_string(),
            connected: true,
            latency_ms: Some(100),
            can_write: true,
            can_read: false,
            round_trip_ms: Some(500),
            payload_size: 32768,
            error: Some("read failed".to_string()),
        };
        assert!(!no_read.is_working());
    }
}
