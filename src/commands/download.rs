use crate::chunking::{FileAssembler, FileChunker};
use crate::config::{get_data_relays, get_index_relays, get_private_key, EncryptionAlgorithm};
use crate::manifest::Manifest;
use crate::nostr::{
    create_chunk_filter, create_chunk_filter_for_indices, create_manifest_filter,
    parse_chunk_event, parse_manifest_event,
};
use crate::session::{compute_hash_sha512, DownloadMeta, DownloadSession};
use indicatif::{ProgressBar, ProgressStyle};
use nostr_sdk::prelude::*;
use sha2::{Digest, Sha256};
use futures::StreamExt;
use std::collections::{HashMap, HashSet};
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Threshold ratio for switching to targeted chunk filters.
/// When missing chunks are less than 1/N of total chunks, use targeted filters
/// (querying specific chunk identifiers) instead of a full filter (querying all chunks).
/// Value of 2 means: use targeted filter when less than 50% of chunks are missing.
const TARGETED_FILTER_THRESHOLD_DIVISOR: usize = 2;

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
            println!("Using data relays for manifest lookup...");
            get_data_relays()?
        } else {
            get_index_relays()
        };

        println!("Fetching manifest for hash: {}", hash);
        fetch_manifest_from_relays(&hash, &relay_list, verbose).await?
    } else {
        return Err(anyhow::anyhow!(
            "Either hash or --manifest is required"
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

    // 3. Check for existing download session
    let file_hash_full = compute_hash_sha512(&manifest.file_hash);
    let session_exists = DownloadSession::exists(&file_hash_full)?;
    let mut resuming = false;

    if session_exists {
        match DownloadSession::open(&file_hash_full) {
            Ok(existing_session) => {
                let downloaded = existing_session.get_downloaded_count()?;
                let total = existing_session.total_chunks;
                drop(existing_session); // Release the lock

                print!(
                    "Resume interrupted download? ({}/{} chunks) [Y/n] ",
                    downloaded, total
                );
                io::stdout().flush()?;

                let mut input = String::new();
                io::stdin().read_line(&mut input)?;

                let input = input.trim().to_lowercase();
                if input.is_empty() || input == "y" || input == "yes" {
                    resuming = true;
                } else {
                    println!("Starting fresh download...");
                    DownloadSession::delete(&file_hash_full)?;
                }
            }
            Err(e) => {
                eprintln!("Warning: Could not open existing session: {}", e);
                eprintln!("Starting fresh download...");
                DownloadSession::delete(&file_hash_full)?;
            }
        }
    }

    // 4. Create or resume download session
    let session = if resuming {
        DownloadSession::open(&file_hash_full)?
    } else {
        let meta = DownloadMeta {
            file_hash: manifest.file_hash.clone(),
            file_hash_full: file_hash_full.clone(),
            file_name: manifest.file_name.clone(),
            file_size: manifest.file_size,
            total_chunks: manifest.total_chunks,
            encryption: manifest.encryption,
            manifest: manifest.clone(),
            output_path: output_path.clone(),
        };
        DownloadSession::create(meta)?
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

    // 5. Fetch chunks from each relay individually for stats
    // Get already-downloaded chunks count for progress bar
    let already_downloaded = session.get_downloaded_count()?;
    if already_downloaded > 0 {
        println!(
            "Resuming: {}/{} chunks already downloaded",
            already_downloaded,
            manifest.total_chunks
        );
    }

    // Set up progress bar for chunk retrieval
    let pb = ProgressBar::new(manifest.total_chunks as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} chunks ({msg})")?
            .progress_chars("█▓░"),
    );
    pb.set_message("starting...");
    pb.enable_steady_tick(Duration::from_millis(100));
    pb.set_position(already_downloaded as u64);

    for (relay_idx, relay_url) in relay_list.iter().enumerate() {
        // Calculate missing chunks at start of each iteration from session
        let missing_indices = session.get_missing_indices()?;

        // Exit early if no missing chunks
        if missing_indices.is_empty() {
            pb.set_position(manifest.total_chunks as u64);
            pb.set_message("complete!");
            break;
        }

        // Use targeted filters when few chunks remain missing (efficient, small filter).
        // Use full filter when many chunks are missing (e.g., after relay failure) to avoid
        // creating extremely large targeted filters with hundreds of identifiers.
        let use_targeted = missing_indices.len() * TARGETED_FILTER_THRESHOLD_DIVISOR < manifest.total_chunks;
        let filters: Vec<Filter> = if use_targeted {
            create_chunk_filter_for_indices(
                &manifest.file_hash,
                &missing_indices,
                Some(&author_pubkey),
            )?
        } else {
            vec![create_chunk_filter(&manifest.file_hash, Some(&author_pubkey))]
        };

        pb.set_message(format!("relay {}/{}", relay_idx + 1, relay_list.len()));

        if verbose {
            pb.suspend(|| println!(
                "  Fetching from: {} ({} chunks needed, {} filter batch{})",
                relay_url,
                missing_indices.len(),
                filters.len(),
                if filters.len() == 1 { "" } else { "es" }
            ));
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

        // Fetch events for each filter batch
        for filter in filters {
            match client.stream_events(filter, Duration::from_secs(30)).await {
                Ok(mut stream) => {
                    relay_stat.connected = true;

                    while let Some(event) = stream.next().await {
                        match parse_chunk_event(&event, decrypt_keys.as_ref()) {
                            Ok(chunk_data) => {
                                relay_stat.chunks_found.insert(chunk_data.index);

                                // Compute chunk hash
                                let mut hasher = Sha256::new();
                                hasher.update(&chunk_data.data);
                                let chunk_hash = format!("sha256:{}", hex::encode(hasher.finalize()));

                                // Store in session (idempotent - INSERT OR REPLACE)
                                session.store_chunk(chunk_data.index, &chunk_data.data, &chunk_hash)?;
                                pb.set_position(session.get_downloaded_count()? as u64);
                            }
                            Err(e) => {
                                if verbose {
                                    pb.suspend(|| eprintln!("    Failed to parse event: {}", e));
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    if verbose {
                        pb.suspend(|| eprintln!("    Fetch error: {}", e));
                    }
                }
            }
        }

        relay_stat.fetch_time_ms = start.elapsed().as_millis() as u64;

        if verbose {
            pb.suspend(|| println!(
                "    Found {} chunks in {}ms",
                relay_stat.chunks_found.len(),
                relay_stat.fetch_time_ms
            ));
        }

        stats.relay_stats.insert(relay_url.clone(), relay_stat);
        client.disconnect().await;
    }

    pb.finish_and_clear();
    let downloaded_count = session.get_downloaded_count()?;
    println!("Retrieved {}/{} chunks\n", downloaded_count, manifest.total_chunks);

    // 6. Check for missing chunks
    let missing = session.get_missing_indices()?;

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

    // 7. Reassemble file from session data
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} Assembling file...")?
    );
    spinner.enable_steady_tick(Duration::from_millis(100));

    let all_chunks = session.get_all_chunks()?;
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

    // Clean up session on success
    session.cleanup()?;

    println!("\n=== Download Summary ===");
    println!("File:   {}", output_path.display());
    println!("Size:   {} bytes", manifest.file_size);
    println!("Chunks: {}/{}", downloaded_count, manifest.total_chunks);
    println!("Hash:   {} ({})", computed_hash, if computed_hash == manifest.file_hash { "OK" } else { "MISMATCH" });

    // 8. Show relay stats if requested
    if show_stats {
        stats.print_report();
    }

    Ok(())
}
