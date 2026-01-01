use serde::Deserialize;
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

    let best: Vec<&str> = relays
        .iter()
        .take(count)
        .map(|r| r.url.as_str())
        .collect();

    // Print in TOML array format
    println!("urls = [");
    for (i, url) in best.iter().enumerate() {
        let comma = if i < best.len() - 1 { "," } else { "" };
        println!("    \"{}\"{}", url, comma);
    }
    println!("]");

    Ok(())
}
