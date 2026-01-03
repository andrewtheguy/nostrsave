use crate::cli::RelaySource;
use crate::config::get_index_relays;
use crate::relay::{discover_relays_from_nostr_watch, test_relays_concurrent, RelayTestResult};
use chrono::Utc;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;
use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

/// JSON output structure for relay discovery results
#[derive(Serialize)]
struct RelayDiscoveryOutput {
    metadata: DiscoveryMetadata,
    working_relays: Vec<RelayTestResult>,
    failed_relays: Vec<RelayTestResult>,
}

#[derive(Serialize)]
struct DiscoveryMetadata {
    generated_by: String,
    version: String,
    timestamp: String,
    settings: DiscoverySettings,
    summary: DiscoverySummary,
}

#[derive(Serialize)]
struct DiscoverySettings {
    timeout_secs: u64,
    concurrent_tests: usize,
    relay_source: String,
    chunk_size: usize,
}

#[derive(Serialize)]
struct DiscoverySummary {
    total_tested: usize,
    working_count: usize,
    failed_count: usize,
    sources: Vec<String>,
}

pub async fn execute(
    relay: Option<String>,
    relay_source: Option<RelaySource>,
    output: PathBuf,
    timeout_secs: u64,
    concurrent: usize,
    chunk_size: usize,
    verbose: bool,
) -> anyhow::Result<()> {
    println!("Discovering relays...");
    println!("  Test payload size: {} bytes", chunk_size);

    let mut all_relays: HashSet<String> = HashSet::new();
    let mut sources: Vec<String> = Vec::new();

    // If a single relay is specified, only test that one
    if let Some(ref relay_url) = relay {
        println!("  Testing single relay: {}", relay_url);
        sources.push(format!("command line ({})", relay_url));
        all_relays.insert(relay_url.clone());
    } else {
        // Use relay_source to determine where to fetch relays from
        let source = relay_source.ok_or_else(|| anyhow::anyhow!("relay_source required when relay not provided"))?;

        match source {
            RelaySource::Nostrwatch => {
                // Fetch from nostr.watch
                match discover_relays_from_nostr_watch().await {
                    Ok(relays) => {
                        println!("  Fetched {} relays from nostr.watch", relays.len());
                        sources.push(format!("nostr.watch ({} relays)", relays.len()));
                        all_relays.extend(relays);
                    }
                    Err(e) => {
                        eprintln!("  Warning: Failed to fetch from nostr.watch: {}", e);
                    }
                }

                // Add index relays
                let index_relays = get_index_relays();
                println!("  Added {} index relays", index_relays.len());
                sources.push(format!("index relays ({} relays)", index_relays.len()));
                all_relays.extend(index_relays);
            }
            RelaySource::ConfiguredOnly => {
                // Only use configured index relays
                let index_relays = get_index_relays();
                println!("  Using {} configured index relays", index_relays.len());
                sources.push(format!("index relays ({} relays)", index_relays.len()));
                all_relays.extend(index_relays);
            }
        }
    }

    if all_relays.is_empty() {
        return Err(anyhow::anyhow!("No relays to test"));
    }

    let relay_list: Vec<String> = all_relays.into_iter().collect();
    println!("  Testing {} unique relays...\n", relay_list.len());

    // 3. Set up progress bar
    let pb = ProgressBar::new(relay_list.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} relays")?
            .progress_chars("#>-"),
    );

    let pb_clone = pb.clone();
    let progress_callback = Box::new(move |done: usize, _total: usize| {
        pb_clone.set_position(done as u64);
    });

    // 4. Test relays concurrently with round-trip payload test
    let timeout = Duration::from_secs(timeout_secs);
    let results = test_relays_concurrent(relay_list, concurrent, timeout, chunk_size, Some(progress_callback)).await;

    pb.finish_and_clear();

    // 5. Single relay mode: print JSON to stdout and exit early
    if relay.is_some() {
        let result = results.first().expect("should have one result");
        let json = serde_json::to_string_pretty(result)?;
        println!("{}", json);
        return Ok(());
    }

    // 6. Separate working and failed
    let mut working: Vec<RelayTestResult> = results.iter().filter(|r| r.is_working()).cloned().collect();
    let mut failed: Vec<RelayTestResult> = results.iter().filter(|r| !r.is_working()).cloned().collect();

    // Sort working relays by round-trip time
    working.sort_by_key(|r| r.round_trip_ms.unwrap_or(u64::MAX));
    // Sort failed relays alphabetically
    failed.sort_by(|a, b| a.url.cmp(&b.url));

    // 7. Bulk mode: print summary and save to file
    println!("Results:");
    for result in &working {
        let connect = result.latency_ms.map(|ms| format!("{}ms", ms)).unwrap_or_else(|| "?".to_string());
        let roundtrip = result.round_trip_ms.map(|ms| format!("{}ms", ms)).unwrap_or_else(|| "?".to_string());
        println!("  \x1b[32m✓\x1b[0m {:<45} connect: {:>6}, round-trip: {:>6}", result.url, connect, roundtrip);
    }

    if verbose {
        for result in &failed {
            let error = result.error.as_deref().unwrap_or("unknown error");
            println!("  \x1b[31m✗\x1b[0m {:<45} - {}", result.url, error);
        }
    } else if !failed.is_empty() {
        println!("  ... and {} failed relays (use --verbose to see)", failed.len());
    }

    println!(
        "\nSummary: {}/{} relays working",
        working.len(),
        results.len()
    );

    // Build JSON output with detailed metadata
    let output_data = RelayDiscoveryOutput {
        metadata: DiscoveryMetadata {
            generated_by: "nostrsave discover-relays".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            settings: DiscoverySettings {
                timeout_secs,
                concurrent_tests: concurrent,
                relay_source: match relay_source {
                    Some(RelaySource::Nostrwatch) => "nostrwatch".to_string(),
                    Some(RelaySource::ConfiguredOnly) => "configured-only".to_string(),
                    None => "unknown".to_string(),
                },
                chunk_size,
            },
            summary: DiscoverySummary {
                total_tested: results.len(),
                working_count: working.len(),
                failed_count: failed.len(),
                sources,
            },
        },
        working_relays: working,
        failed_relays: failed,
    };

    // Save to JSON file
    let json = serde_json::to_string_pretty(&output_data)?;
    let mut file = File::create(&output)?;
    file.write_all(json.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;

    println!("Saved to: {}", output.display());

    // Suggest next step
    println!(
        "\nTo get the best relays for your config:\n  nostrsave best-relays {}",
        output.display()
    );

    Ok(())
}
