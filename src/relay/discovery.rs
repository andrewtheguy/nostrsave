use base64::prelude::*;
use futures::stream::{self, StreamExt};
use nostr_sdk::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

/// Kind for test chunk events (same as file chunks)
const TEST_CHUNK_KIND: u16 = 30089;

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

/// Test a single relay for connectivity and round-trip with chunk-sized payload
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

    // Wait for connection (with timeout)
    let connect_start = Instant::now();
    let mut connected = false;
    while connect_start.elapsed() < timeout {
        let relays = client.relays().await;
        if let Some((_, relay)) = relays.into_iter().next() {
            if relay.is_connected() {
                connected = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

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
    let test_id = format!("test-{}", rand_hex(16));
    let test_data: Vec<u8> = (0..chunk_size).map(|i| (i % 256) as u8).collect();
    let test_data_b64 = BASE64_STANDARD.encode(&test_data);
    let test_hash = format!("sha256:{}", hex::encode(Sha256::digest(&test_data)));

    // Create a test chunk event
    let tags = vec![
        Tag::custom(TagKind::Custom("d".into()), vec![test_id.clone()]),
        Tag::custom(TagKind::Custom("x".into()), vec![test_hash.clone()]),
        Tag::custom(TagKind::Custom("chunk".into()), vec!["0".to_string()]),
    ];

    let round_trip_start = Instant::now();

    // Publish test event
    let can_write = match tokio::time::timeout(timeout, async {
        let builder = EventBuilder::new(Kind::Custom(TEST_CHUNK_KIND), &test_data_b64).tags(tags);
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
    let filter = Filter::new()
        .kind(Kind::Custom(TEST_CHUNK_KIND))
        .author(keys.public_key())
        .identifier(test_id.clone())
        .limit(1);

    let (can_read, error) = match client.fetch_events(filter, timeout).await {
        Ok(events) => {
            if let Some(event) = events.iter().next() {
                // Verify the content matches
                if event.content == test_data_b64 {
                    (true, None)
                } else {
                    (false, Some("Content mismatch on read".to_string()))
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

/// Generate random hex string using cryptographically secure RNG
fn rand_hex(len: usize) -> String {
    // Use nostr_sdk's key generation which uses a secure RNG
    let keys = Keys::generate();
    let secret_bytes = keys.secret_key().as_secret_bytes();
    hex::encode(&secret_bytes[..len.min(32)])
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
            payload_size: 65536,
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
            payload_size: 65536,
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
            payload_size: 65536,
            error: Some("read failed".to_string()),
        };
        assert!(!no_read.is_working());
    }
}
