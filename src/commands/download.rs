use crate::chunking::{FileAssembler, FileChunker};
use crate::config::DEFAULT_RELAYS;
use crate::manifest::Manifest;
use crate::nostr::{create_chunk_filter, create_manifest_filter, parse_chunk_event, parse_manifest_event};
use indicatif::{ProgressBar, ProgressStyle};
use nostr_sdk::prelude::*;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Statistics for a single relay
#[derive(Debug, Default)]
pub struct RelayStats {
    pub chunks_found: HashSet<usize>,
    pub fetch_time_ms: u64,
    pub connected: bool,
}

/// Overall download statistics
#[derive(Debug, Default)]
pub struct DownloadStats {
    pub relay_stats: HashMap<String, RelayStats>,
    pub total_chunks: usize,
}

impl DownloadStats {
    pub fn print_report(&self) {
        println!("\n=== Relay Statistics ===");
        println!(
            "{:<40} {:>12} {:>10}",
            "Relay", "Chunks", "Avg Time"
        );
        println!("{}", "-".repeat(65));

        let mut relays: Vec<_> = self.relay_stats.iter().collect();
        relays.sort_by(|a, b| b.1.chunks_found.len().cmp(&a.1.chunks_found.len()));

        for (relay, stats) in relays {
            let found = stats.chunks_found.len();
            let pct = if self.total_chunks == 0 {
                0.0
            } else {
                (found as f64 / self.total_chunks as f64) * 100.0
            };
            let status = if stats.connected { "" } else { " (failed)" };

            println!(
                "{:<40} {:>5}/{:<5} ({:>5.1}%) {:>6}ms{}",
                relay,
                found,
                self.total_chunks,
                pct,
                stats.fetch_time_ms,
                status
            );
        }

        // Find chunks missing from each relay
        println!("\n=== Missing Chunks by Relay ===");
        for (relay, stats) in &self.relay_stats {
            if stats.chunks_found.len() < self.total_chunks {
                let missing: Vec<usize> = (0..self.total_chunks)
                    .filter(|i| !stats.chunks_found.contains(i))
                    .collect();
                if !missing.is_empty() {
                    println!("  {}: {:?}", relay, missing);
                }
            }
        }
    }
}

/// Fetch manifest from relays by file hash
async fn fetch_manifest_from_relays(
    file_hash: &str,
    relays: &[String],
    verbose: bool,
) -> anyhow::Result<Manifest> {
    let keys = Keys::generate();
    let filter = create_manifest_filter(file_hash);

    for relay_url in relays {
        if verbose {
            println!("  Trying relay: {}", relay_url);
        }

        let client = Client::new(keys.clone());
        if client.add_relay(relay_url).await.is_err() {
            continue;
        }

        client.connect().await;
        tokio::time::sleep(Duration::from_millis(500)).await;

        match client.fetch_events(filter.clone(), Duration::from_secs(10)).await {
            Ok(events) => {
                if let Some(event) = events.iter().next() {
                    match parse_manifest_event(event) {
                        Ok(manifest) => {
                            client.disconnect().await;
                            return Ok(manifest);
                        }
                        Err(e) => {
                            if verbose {
                                eprintln!("    Failed to parse manifest: {}", e);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                if verbose {
                    eprintln!("    Fetch error: {}", e);
                }
            }
        }

        client.disconnect().await;
    }

    Err(anyhow::anyhow!("Manifest not found on any relay"))
}

pub async fn execute(
    manifest_path: Option<PathBuf>,
    file_hash: Option<String>,
    output: Option<PathBuf>,
    show_stats: bool,
    private_key: Option<String>,
    relays: Vec<String>,
    verbose: bool,
) -> anyhow::Result<()> {
    // 1. Load manifest from file or fetch from relays
    let manifest = if let Some(path) = manifest_path {
        Manifest::load_from_file(&path)?
    } else if let Some(hash) = file_hash {
        // Use provided relays or defaults
        let relay_list: Vec<String> = if relays.is_empty() {
            DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect()
        } else {
            relays.clone()
        };

        println!("Fetching manifest for hash: {}", hash);
        fetch_manifest_from_relays(&hash, &relay_list, verbose).await?
    } else {
        return Err(anyhow::anyhow!(
            "Either manifest file or --hash is required"
        ));
    };

    println!("Downloading: {} ({} bytes)", manifest.file_name, manifest.file_size);
    println!("File hash:   {}", manifest.file_hash);
    println!("Chunks:      {}", manifest.total_chunks);
    println!("Chunk size:  {} bytes", manifest.chunk_size);

    // 2. Setup client
    let keys = match private_key {
        Some(key) => Keys::parse(&key)?,
        None => Keys::generate(),
    };

    // Parse pubkey from manifest
    let author_pubkey = PublicKey::parse(&manifest.pubkey)?;

    // Use relays from manifest, override with CLI if provided
    let relay_list = if relays.is_empty() {
        manifest.relays.clone()
    } else {
        relays
    };

    println!("\nConnecting to {} relays...", relay_list.len());

    let mut stats = DownloadStats {
        total_chunks: manifest.total_chunks,
        ..Default::default()
    };

    // 3. Fetch chunks from each relay individually for stats
    let mut all_chunks: HashMap<usize, Vec<u8>> = HashMap::new();

    let filter = create_chunk_filter(&manifest.file_hash, Some(&author_pubkey));

    for relay_url in &relay_list {
        if verbose {
            println!("  Fetching from: {}", relay_url);
        }

        let client = Client::new(keys.clone());
        let mut relay_stat = RelayStats::default();

        if let Err(e) = client.add_relay(relay_url).await {
            eprintln!("  Failed to add relay {}: {}", relay_url, e);
            stats.relay_stats.insert(relay_url.clone(), relay_stat);
            continue;
        }

        client.connect().await;
        tokio::time::sleep(Duration::from_millis(500)).await;

        let start = Instant::now();

        match client.fetch_events(filter.clone(), Duration::from_secs(30)).await {
            Ok(events) => {
                relay_stat.connected = true;
                relay_stat.fetch_time_ms = start.elapsed().as_millis() as u64;

                for event in events.iter() {
                    match parse_chunk_event(event) {
                        Ok(chunk_data) => {
                            relay_stat.chunks_found.insert(chunk_data.index);

                            // Only store if we don't have this chunk yet
                            if let std::collections::hash_map::Entry::Vacant(e) = all_chunks.entry(chunk_data.index) {
                                e.insert(chunk_data.data);
                            }
                        }
                        Err(e) => {
                            if verbose {
                                eprintln!("    Failed to parse event: {}", e);
                            }
                        }
                    }
                }

                if verbose {
                    println!(
                        "    Found {} chunks in {}ms",
                        relay_stat.chunks_found.len(),
                        relay_stat.fetch_time_ms
                    );
                }
            }
            Err(e) => {
                relay_stat.fetch_time_ms = start.elapsed().as_millis() as u64;
                if verbose {
                    eprintln!("    Fetch error: {}", e);
                }
            }
        }

        stats.relay_stats.insert(relay_url.clone(), relay_stat);
        client.disconnect().await;
    }

    println!("\nRetrieved {}/{} chunks", all_chunks.len(), manifest.total_chunks);

    // 4. Check for missing chunks
    let missing: Vec<usize> = (0..manifest.total_chunks)
        .filter(|i| !all_chunks.contains_key(i))
        .collect();

    if !missing.is_empty() {
        println!("\nERROR: Missing {} chunks: {:?}", missing.len(), missing);
        if show_stats {
            stats.print_report();
        }
        return Err(anyhow::anyhow!(
            "Cannot reassemble file: missing {} chunks",
            missing.len()
        ));
    }

    // 5. Reassemble file
    let output_path = output.unwrap_or_else(|| PathBuf::from(&manifest.file_name));

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} Assembling file...")?
    );
    spinner.enable_steady_tick(Duration::from_millis(100));

    let assembler = FileAssembler::new();
    assembler.assemble(&all_chunks, manifest.total_chunks, &output_path)?;
    spinner.finish_and_clear();

    // 6. Verify file hash
    println!("Verifying file integrity...");
    let chunker = FileChunker::new(manifest.chunk_size)?;
    let computed_hash = chunker.compute_file_hash(&output_path)?;

    if computed_hash != manifest.file_hash {
        println!("\nWARNING: File hash mismatch!");
        println!("  Expected: {}", manifest.file_hash);
        println!("  Got:      {}", computed_hash);
    } else {
        println!("File hash verified successfully!");
    }

    println!("\n=== Download Summary ===");
    println!("File:   {}", output_path.display());
    println!("Size:   {} bytes", manifest.file_size);
    println!("Chunks: {}/{}", all_chunks.len(), manifest.total_chunks);
    println!("Hash:   {} ({})", computed_hash, if computed_hash == manifest.file_hash { "OK" } else { "MISMATCH" });

    // 7. Show relay stats if requested
    if show_stats {
        stats.print_report();
    }

    Ok(())
}
