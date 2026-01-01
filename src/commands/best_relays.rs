use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
struct RelayDiscoveryOutput {
    working_relays: Vec<RelayResult>,
}

#[derive(Deserialize)]
struct RelayResult {
    url: String,
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

    // Take top N relays (already sorted by round-trip time in discovery)
    let best: Vec<&str> = data
        .working_relays
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
