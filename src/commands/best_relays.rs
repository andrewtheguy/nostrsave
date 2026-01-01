use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Deserialize)]
struct RelayDiscoveryOutput {
    working_relays: Vec<RelayResult>,
}

#[derive(Deserialize)]
struct RelayResult {
    url: String,
    round_trip_ms: u64,
}

/// Output structure for TOML serialization
#[derive(Serialize)]
struct RelayUrls {
    urls: Vec<String>,
}

pub fn execute(input: PathBuf, count: usize) -> anyhow::Result<()> {
    // Read and parse JSON file
    let content = std::fs::read_to_string(&input)
        .map_err(|e| anyhow::anyhow!("Failed to read '{}': {}", input.display(), e))?;

    let data: RelayDiscoveryOutput = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse JSON: {}", e))?;

    if data.working_relays.is_empty() {
        println!("No working relays found in {}", input.display());
        return Ok(());
    }

    // Sort by round-trip time and take top N fastest relays
    let mut relays = data.working_relays;
    relays.sort_by_key(|r| r.round_trip_ms);

    let urls: Vec<String> = relays
        .iter()
        .take(count)
        .map(|r| r.url.clone())
        .collect();

    // Serialize to TOML format
    let output = RelayUrls { urls };
    let toml_str = toml::to_string_pretty(&output)
        .map_err(|e| anyhow::anyhow!("Failed to serialize to TOML: {}", e))?;

    print!("{}", toml_str);

    Ok(())
}
