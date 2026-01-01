use base64::Engine;
use crate::chunking::FileChunker;
use crate::config::{get_data_relays, get_index_relays, get_private_key, EncryptionAlgorithm};
use crate::crypto;
use crate::manifest::Manifest;
use crate::nostr::{
    create_chunk_event, create_file_index_event, create_file_index_filter, create_manifest_event,
    parse_file_index_event, ChunkMetadata, FileIndex, FileIndexEntry,
};
use indicatif::{ProgressBar, ProgressStyle};
use nostr_sdk::prelude::*;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Maximum number of retry attempts for publishing events
const MAX_RETRIES: u32 = 3;
/// Base delay for exponential backoff (doubles each retry)
const BASE_RETRY_DELAY_MS: u64 = 500;
/// Maximum delay cap for retries
const MAX_RETRY_DELAY_MS: u64 = 5000;

pub async fn execute(
    file: PathBuf,
    chunk_size: usize,
    output: Option<PathBuf>,
    key_file: Option<&str>,
    encryption: EncryptionAlgorithm,
    verbose: bool,
) -> anyhow::Result<()> {
    // 1. Load config - private key and relays
    let private_key = get_private_key(key_file)?;
    let keys = Keys::parse(&private_key)?;

    let data_relays = get_data_relays()?;
    let index_relays = get_index_relays();

    if index_relays.is_empty() {
        return Err(anyhow::anyhow!(
            "No index relays configured. Add [index_relays] to config or check relay URLs."
        ));
    }

    // 2. Verify file exists
    if !file.exists() {
        return Err(anyhow::anyhow!("File not found: {}", file.display()));
    }

    // 3. Confirm unencrypted upload
    if encryption == EncryptionAlgorithm::None {
        println!("WARNING: File will be uploaded WITHOUT encryption to public relays.");
        println!("         Anyone can read the file contents.");
        print!("Continue? [y/N] ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        let input = input.trim().to_lowercase();
        if input != "y" && input != "yes" {
            println!("Upload cancelled.");
            return Ok(());
        }
    }

    let file_name = file
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Invalid file path"))?
        .to_string_lossy()
        .to_string();
    let file_size = std::fs::metadata(&file)?.len();

    println!("File: {} ({} bytes)", file_name, file_size);

    // 4. Split file into chunks
    println!("Splitting file into chunks...");
    let chunker = FileChunker::new(chunk_size)?;
    let (file_hash, chunks) = chunker.split_file(&file)?;

    println!("File hash: {}", file_hash);
    println!(
        "Created {} chunks of up to {} bytes each",
        chunks.len(),
        chunk_size
    );

    // 4. Setup client and connect to data relays
    println!("\nConnecting to {} data relays...", data_relays.len());

    let client = Client::new(keys.clone());
    let mut added_relays = Vec::new();
    for relay in &data_relays {
        match client.add_relay(relay).await {
            Ok(_) => {
                added_relays.push(relay.clone());
                if verbose {
                    println!("  Added relay: {}", relay);
                }
            }
            Err(e) => {
                eprintln!("  Failed to add relay {}: {}", relay, e);
            }
        }
    }

    if added_relays.is_empty() {
        return Err(anyhow::anyhow!("No relays could be added"));
    }

    client.connect().await;
    client.wait_for_connection(Duration::from_secs(10)).await;

    // Verify at least one relay is connected
    let connected_relays: Vec<_> = client
        .relays()
        .await
        .into_iter()
        .filter(|(_, r)| r.is_connected())
        .map(|(url, _)| url.to_string())
        .collect();

    if connected_relays.is_empty() {
        return Err(anyhow::anyhow!(
            "No relays connected. Added {} relays but none established connection.",
            added_relays.len()
        ));
    }

    println!(
        "Connected to {}/{} relays",
        connected_relays.len(),
        added_relays.len()
    );
    if verbose {
        for relay in &connected_relays {
            println!("  Connected: {}", relay);
        }
    }

    // 5. Create manifest (store data relays in manifest for download)
    let mut manifest = Manifest::new(
        file_name.clone(),
        file_hash.clone(),
        file_size,
        chunk_size,
        keys.public_key().to_bech32()?,
        data_relays.clone(),
        encryption,
    );

    println!("Encryption: {}", encryption);

    // 6. Publish chunks with progress
    println!("\nUploading {} chunks...", chunks.len());
    let pb = ProgressBar::new(chunks.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} chunks ({eta})")?
            .progress_chars("#>-"),
    );

    for chunk in &chunks {
        // Prepare content: encrypt or base64-encode
        let content = if encryption == EncryptionAlgorithm::Nip44 {
            crypto::encrypt_chunk(&keys, &chunk.data)?
        } else {
            base64::engine::general_purpose::STANDARD.encode(&chunk.data)
        };

        let metadata = ChunkMetadata {
            file_hash: &file_hash,
            chunk_index: chunk.index,
            total_chunks: manifest.total_chunks,
            chunk_hash: &chunk.hash,
            chunk_data: &chunk.data,
            filename: &file_name,
            encryption,
        };

        // Retry loop with exponential backoff
        let mut last_error = None;
        for attempt in 0..=MAX_RETRIES {
            let event_builder = create_chunk_event(&metadata, &content)?;

            match client.send_event_builder(event_builder).await {
                Ok(output) => {
                    let event_id = output.val.to_bech32()?;
                    if verbose {
                        println!("  Chunk {} -> {}", chunk.index, event_id);
                    }
                    manifest.add_chunk(chunk.index, event_id, chunk.hash.clone())?;
                    last_error = None;
                    break;
                }
                Err(e) => {
                    last_error = Some(e);
                    if attempt < MAX_RETRIES {
                        // Calculate delay with exponential backoff and jitter
                        let base_delay = BASE_RETRY_DELAY_MS * 2u64.pow(attempt);
                        let jitter = (SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .subsec_nanos()
                            % 200) as u64;
                        let delay = (base_delay + jitter).min(MAX_RETRY_DELAY_MS);

                        if verbose {
                            pb.suspend(|| {
                                eprintln!(
                                    "  Chunk {} failed (attempt {}/{}), retrying in {}ms...",
                                    chunk.index,
                                    attempt + 1,
                                    MAX_RETRIES + 1,
                                    delay
                                );
                            });
                        }
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                    }
                }
            }
        }

        if let Some(e) = last_error {
            pb.finish_and_clear();
            return Err(anyhow::anyhow!(
                "Failed to publish chunk {} after {} attempts: {}",
                chunk.index,
                MAX_RETRIES + 1,
                e
            ));
        }

        pb.inc(1);
    }

    pb.finish_with_message("Upload complete!");

    // 7. Publish manifest to data relays
    println!("\nPublishing manifest to data relays...");
    let manifest_event = create_manifest_event(&manifest)?;
    match client.send_event_builder(manifest_event.clone()).await {
        Ok(_) => {}
        Err(e) => {
            return Err(anyhow::anyhow!("Failed to publish manifest: {}", e));
        }
    };

    client.disconnect().await;

    // 8. Publish manifest and update file index on index relays
    println!("Publishing to index relays...");
    let manifest_event_id = publish_to_index_relays(
        &keys,
        &index_relays,
        manifest_event,
        &file_hash,
        &file_name,
        file_size,
        manifest.created_at,
        encryption,
        verbose,
    )
    .await?;

    // 9. Save manifest locally as backup
    let manifest_path = output.unwrap_or_else(|| PathBuf::from(format!("{}.nostrsave", file_name)));
    manifest.save_to_file(&manifest_path)?;

    println!("\n=== Upload Summary ===");
    println!("File:       {}", file_name);
    println!("Size:       {} bytes", file_size);
    println!("Chunks:     {}", manifest.total_chunks);
    println!("Hash:       {}", file_hash);
    println!("Manifest:   {}", manifest_event_id);
    println!("Local copy: {}", manifest_path.display());
    println!("\nDownload with:");
    println!("  nostrsave download --hash {}", file_hash);
    println!("  nostrsave download {}", manifest_path.display());

    Ok(())
}

/// Publish manifest and update file index on index relays
#[allow(clippy::too_many_arguments)]
async fn publish_to_index_relays(
    keys: &Keys,
    index_relays: &[String],
    manifest_event: EventBuilder,
    file_hash: &str,
    file_name: &str,
    file_size: u64,
    uploaded_at: u64,
    encryption: EncryptionAlgorithm,
    verbose: bool,
) -> anyhow::Result<String> {
    let client = Client::new(keys.clone());

    // 1. Add index relays and validate at least one succeeds
    let mut added_count = 0;
    for relay in index_relays {
        match client.add_relay(relay).await {
            Ok(_) => {
                added_count += 1;
            }
            Err(e) => {
                if verbose {
                    eprintln!("  Failed to add index relay {}: {}", relay, e);
                }
            }
        }
    }

    if added_count == 0 {
        return Err(anyhow::anyhow!(
            "No index relays could be added. Tried {} relays.",
            index_relays.len()
        ));
    }

    client.connect().await;
    client.wait_for_connection(Duration::from_secs(10)).await;

    // Verify at least one relay is connected
    let connected_relays: Vec<_> = client
        .relays()
        .await
        .into_iter()
        .filter(|(_, r)| r.is_connected())
        .map(|(url, _)| url.to_string())
        .collect();

    if connected_relays.is_empty() {
        return Err(anyhow::anyhow!(
            "No index relays connected. Added {} relays but none established connection.",
            added_count
        ));
    }

    if verbose {
        println!(
            "  Connected to {}/{} index relays",
            connected_relays.len(),
            added_count
        );
    }

    // 2. Publish manifest to index relays
    let manifest_event_id = match client.send_event_builder(manifest_event).await {
        Ok(output) => output.val.to_bech32()?,
        Err(e) => {
            client.disconnect().await;
            return Err(anyhow::anyhow!("Failed to publish manifest to index relays: {}", e));
        }
    };

    // 2. Fetch existing file index (select most recent by created_at)
    let filter = create_file_index_filter(&keys.public_key());
    let mut index = match client.fetch_events(filter, Duration::from_secs(10)).await {
        Ok(events) => {
            if let Some(event) = events.iter().max_by_key(|e| e.created_at) {
                match parse_file_index_event(event) {
                    Ok(existing_index) => {
                        if verbose {
                            println!("  Found existing index with {} files", existing_index.len());
                        }
                        existing_index
                    }
                    Err(e) => {
                        if verbose {
                            eprintln!("  Failed to parse existing index: {}", e);
                        }
                        FileIndex::new()
                    }
                }
            } else {
                if verbose {
                    println!("  No existing index found, creating new one");
                }
                FileIndex::new()
            }
        }
        Err(e) => {
            eprintln!("WARNING: Failed to fetch existing index. Previous entries may be overwritten.");
            if verbose {
                eprintln!("  Error: {}", e);
            }
            FileIndex::new()
        }
    };

    // 3. Add new entry
    let entry = FileIndexEntry::new(
        file_hash.to_string(),
        file_name.to_string(),
        file_size,
        uploaded_at,
        encryption,
    )?;
    index.add_entry(entry);

    // 4. Publish updated index
    match create_file_index_event(&index) {
        Ok(event_builder) => {
            match client.send_event_builder(event_builder).await {
                Ok(_) => {
                    if verbose {
                        println!("  Index updated with {} files", index.len());
                    }
                }
                Err(e) => {
                    eprintln!("WARNING: Failed to publish file index. File may not appear in 'nostrsave list'.");
                    if verbose {
                        eprintln!("  Error: {}", e);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("WARNING: Failed to create file index event; file index not published.");
            if verbose {
                eprintln!("  Error: {}", e);
            }
        }
    }

    client.disconnect().await;
    Ok(manifest_event_id)
}
