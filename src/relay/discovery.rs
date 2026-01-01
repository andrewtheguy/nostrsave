use futures::stream::{self, StreamExt};
use nostr_sdk::prelude::*;
use std::time::{Duration, Instant};

/// Result of testing a single relay
#[derive(Debug, Clone)]
pub struct RelayTestResult {
    pub url: String,
    pub connected: bool,
    pub latency_ms: Option<u64>,
    pub can_fetch: bool,
    pub error: Option<String>,
}

impl RelayTestResult {
    /// Check if the relay is considered working
    pub fn is_working(&self) -> bool {
        self.connected && self.can_fetch
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

/// Test a single relay for connectivity and functionality
pub async fn test_relay(url: &str, timeout: Duration) -> RelayTestResult {
    let start = Instant::now();

    // Create a temporary keypair for testing
    let keys = Keys::generate();
    let client = Client::new(keys);

    // Try to add the relay
    if let Err(e) = client.add_relay(url).await {
        return RelayTestResult {
            url: url.to_string(),
            connected: false,
            latency_ms: None,
            can_fetch: false,
            error: Some(format!("Failed to add relay: {}", e)),
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
            url: url.to_string(),
            connected: false,
            latency_ms: Some(start.elapsed().as_millis() as u64),
            can_fetch: false,
            error: Some("Connection timeout".to_string()),
        };
    }

    let connect_latency = start.elapsed().as_millis() as u64;

    // Test fetch capability - try to fetch recent events
    let filter = Filter::new()
        .kind(Kind::TextNote)
        .limit(1);

    let can_fetch = match tokio::time::timeout(
        timeout,
        client.fetch_events(filter, timeout),
    )
    .await
    {
        Ok(Ok(_)) => true,
        Ok(Err(_)) => false,
        Err(_) => false, // Timeout
    };

    client.disconnect().await;

    RelayTestResult {
        url: url.to_string(),
        connected: true,
        latency_ms: Some(connect_latency),
        can_fetch,
        error: if can_fetch {
            None
        } else {
            Some("Fetch test failed".to_string())
        },
    }
}

/// Test multiple relays concurrently
pub async fn test_relays_concurrent(
    urls: Vec<String>,
    concurrency: usize,
    timeout: Duration,
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
                let result = test_relay(&url, timeout).await;

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
            can_fetch: true,
            error: None,
        };
        assert!(working.is_working());

        let not_connected = RelayTestResult {
            url: "wss://test.relay".to_string(),
            connected: false,
            latency_ms: None,
            can_fetch: false,
            error: Some("timeout".to_string()),
        };
        assert!(!not_connected.is_working());

        let no_fetch = RelayTestResult {
            url: "wss://test.relay".to_string(),
            connected: true,
            latency_ms: Some(100),
            can_fetch: false,
            error: Some("fetch failed".to_string()),
        };
        assert!(!no_fetch.is_working());
    }
}
