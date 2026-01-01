use crate::chunking::{FileAssembler, FileChunker};
use crate::config::{get_data_relays, get_index_relays, get_private_key, EncryptionAlgorithm};
use crate::manifest::Manifest;
use crate::nostr::{create_chunk_filter, create_manifest_filter, parse_chunk_event, parse_manifest_event};
use indicatif::{ProgressBar, ProgressStyle};
use nostr_sdk::prelude::*;
use std::collections::{HashMap, HashSet};
use std::io::{self, Write};
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
        client.wait_for_connection(Duration::from_secs(5)).await;

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
    key_file: Option<&str>,
    show_stats: bool,
    from_data_relays: bool,
    verbose: bool,
) -> anyhow::Result<()> {
    // 1. Load manifest from file or fetch from relays
    let manifest = if let Some(path) = manifest_path {
        Manifest::load_from_file(&path)?
    } else if let Some(hash) = file_hash {
        // Use index or data relays to fetch manifest based on flag
        let relay_list = if from_data_relays {
            let relays = get_data_relays()?;
            println!("Using data relays for manifest lookup...");
            relays
        } else {
            get_index_relays()?
        };

        println!("Fetching manifest for hash: {}", hash);
        fetch_manifest_from_relays(&hash, &relay_list, verbose).await?
    } else {
        return Err(anyhow::anyhow!(
            "Either manifest file or --hash is required"
        ));
    };

    // Determine output path early to check for existing file
    let output_path = output.unwrap_or_else(|| PathBuf::from(&manifest.file_name));

    // Check if output file already exists
    if output_path.exists() {
        println!("File already exists: {}", output_path.display());
        print!("Overwrite? [y/N] ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        let input = input.trim().to_lowercase();
        if input != "y" && input != "yes" {
            println!("Download cancelled.");
            return Ok(());
        }
    }

    println!("Downloading: {} ({} bytes)", manifest.file_name, manifest.file_size);
    println!("File hash:   {}", manifest.file_hash);
    println!("Chunks:      {}", manifest.total_chunks);
    println!("Chunk size:  {} bytes", manifest.chunk_size);
    println!("Encryption:  {}", manifest.encryption);

    // 2. Setup decryption keys if file is encrypted
    let decrypt_keys = if manifest.encryption == EncryptionAlgorithm::Nip44 {
        let private_key = get_private_key(key_file)?;
        let keys = Keys::parse(&private_key)?;

        // Verify pubkey matches manifest
        let manifest_pubkey = PublicKey::parse(&manifest.pubkey)?;
        if keys.public_key() != manifest_pubkey {
            return Err(anyhow::anyhow!(
                "Key mismatch: your pubkey doesn't match the file's pubkey.\n\
                 File was encrypted by: {}\n\
                 Your pubkey: {}",
                manifest.pubkey,
                keys.public_key().to_bech32()?
            ));
        }
        Some(keys)
    } else {
        None
    };

    // Use random keys for relay connection (read-only access)
    let client_keys = Keys::generate();

    // Parse pubkey from manifest
    let author_pubkey = PublicKey::parse(&manifest.pubkey)?;

    // Use relays from manifest (data relays where chunks are stored)
    let relay_list = manifest.relays.clone();

    if relay_list.is_empty() {
        return Err(anyhow::anyhow!("Manifest contains no relay URLs"));
    }

    println!("\nConnecting to {} relays...\n", relay_list.len());

    let mut stats = DownloadStats {
        total_chunks: manifest.total_chunks,
        ..Default::default()
    };

    // 3. Fetch chunks from each relay individually for stats
    let mut all_chunks: HashMap<usize, Vec<u8>> = HashMap::new();

    let filter = create_chunk_filter(&manifest.file_hash, Some(&author_pubkey));

    // Set up progress bar for chunk retrieval
    let pb = ProgressBar::new(manifest.total_chunks as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} chunks ({msg})")?
            .progress_chars("█▓░"),
    );
    pb.set_message("starting...");
    pb.enable_steady_tick(Duration::from_millis(100));

    for (relay_idx, relay_url) in relay_list.iter().enumerate() {
        pb.set_message(format!("relay {}/{}", relay_idx + 1, relay_list.len()));

        if verbose {
            pb.suspend(|| println!("  Fetching from: {}", relay_url));
        }

        let client = Client::new(client_keys.clone());
        let mut relay_stat = RelayStats::default();

        if let Err(e) = client.add_relay(relay_url).await {
            if verbose {
                pb.suspend(|| eprintln!("  Failed to add relay {}: {}", relay_url, e));
            }
            stats.relay_stats.insert(relay_url.clone(), relay_stat);
            continue;
        }

        client.connect().await;
        client.wait_for_connection(Duration::from_secs(5)).await;

        let start = Instant::now();

        match client.fetch_events(filter.clone(), Duration::from_secs(30)).await {
            Ok(events) => {
                relay_stat.connected = true;
                relay_stat.fetch_time_ms = start.elapsed().as_millis() as u64;

                for event in events.iter() {
                    match parse_chunk_event(event, decrypt_keys.as_ref()) {
                        Ok(chunk_data) => {
                            relay_stat.chunks_found.insert(chunk_data.index);

                            // Only store if we don't have this chunk yet
                            if let std::collections::hash_map::Entry::Vacant(e) = all_chunks.entry(chunk_data.index) {
                                e.insert(chunk_data.data);
                                pb.set_position(all_chunks.len() as u64);
                            }
                        }
                        Err(e) => {
                            if verbose {
                                pb.suspend(|| eprintln!("    Failed to parse event: {}", e));
                            }
                        }
                    }
                }

                if verbose {
                    pb.suspend(|| println!(
                        "    Found {} chunks in {}ms",
                        relay_stat.chunks_found.len(),
                        relay_stat.fetch_time_ms
                    ));
                }
            }
            Err(e) => {
                relay_stat.fetch_time_ms = start.elapsed().as_millis() as u64;
                if verbose {
                    pb.suspend(|| eprintln!("    Fetch error: {}", e));
                }
            }
        }

        stats.relay_stats.insert(relay_url.clone(), relay_stat);
        client.disconnect().await;

        // Exit early if we have all chunks
        if all_chunks.len() == manifest.total_chunks {
            pb.set_position(manifest.total_chunks as u64);
            pb.set_message("complete!");
            break;
        }
    }

    pb.finish_and_clear();
    println!("Retrieved {}/{} chunks\n", all_chunks.len(), manifest.total_chunks);

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
