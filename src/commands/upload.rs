use base64::Engine;
use crate::chunking::FileChunker;
use crate::config::{get_data_relays, get_index_relays, get_private_key, EncryptionAlgorithm};
use crate::crypto;
use crate::manifest::Manifest;
use crate::nostr::{
    create_chunk_event, create_file_index_event, create_file_index_filter, create_manifest_event,
    parse_file_index_event, ChunkMetadata, FileIndex, FileIndexEntry,
};
use crate::session::{compute_file_sha512, UploadMeta, UploadSession};
use indicatif::{ProgressBar, ProgressStyle};
use nostr_sdk::prelude::*;
use std::collections::HashSet;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Maximum number of retry attempts for publishing events
const MAX_RETRIES: u32 = 3;
/// Base delay for exponential backoff (doubles each retry)
const BASE_RETRY_DELAY_MS: u64 = 500;
/// Maximum delay cap for retries
const MAX_RETRY_DELAY_MS: u64 = 5000;

/// Maximum number of retry attempts for opening session database
const SESSION_OPEN_RETRIES: u32 = 3;
/// Delay between session open retries in milliseconds
const SESSION_RETRY_DELAY_MS: u64 = 200;

/// Classify whether an error is likely transient (worth retrying) or irrecoverable.
/// Returns true if the error appears transient (I/O, lock contention, etc.)
fn is_transient_error(err: &anyhow::Error) -> bool {
    let err_str = err.to_string().to_lowercase();

    // SQLite transient errors
    if err_str.contains("database is locked")
        || err_str.contains("sqlite_busy")
        || err_str.contains("unable to open database")
        || err_str.contains("disk i/o error")
    {
        return true;
    }

    // General I/O transient errors
    if err_str.contains("resource temporarily unavailable")
        || err_str.contains("interrupted")
        || err_str.contains("would block")
    {
        return true;
    }

    false
}

/// Classify whether an error indicates irrecoverable corruption.
fn is_corruption_error(err: &anyhow::Error) -> bool {
    let err_str = err.to_string().to_lowercase();

    // Schema version mismatch is recoverable by deletion
    if err_str.contains("schema version mismatch") {
        return true;
    }

    // SQLite corruption
    if err_str.contains("database disk image is malformed")
        || err_str.contains("database is corrupt")
        || err_str.contains("sqlite_corrupt")
        || err_str.contains("file is not a database")
    {
        return true;
    }

    false
}

pub async fn execute(
    file: PathBuf,
    chunk_size: usize,
    output: Option<PathBuf>,
    key_file: Option<&str>,
    encryption: EncryptionAlgorithm,
    force: bool,
    verbose: bool,
) -> anyhow::Result<()> {
    // 1. Load config - private key and relays
    let private_key = get_private_key(key_file)?;
    let keys = Keys::parse(&private_key)?;

    let data_relays = get_data_relays()?;
    let index_relays = get_index_relays();

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

    // Non-UTF-8 file names are rejected
    let file_name = file
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Invalid file path"))?
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("File name contains invalid UTF-8"))?
        .to_string();
    let file_size = std::fs::metadata(&file)?.len();

    println!("File: {} ({} bytes)", file_name, file_size);

    // 4. Compute SHA512 for session tracking and split file into chunks
    println!("Computing file hash...");
    let file_hash_full = compute_file_sha512(&file)?;

    // Check for existing session
    let session_exists = UploadSession::exists(&file_hash_full)?;
    let mut resuming = false;

    if session_exists {
        // Try to open session with retry logic for transient errors
        let mut last_error: Option<anyhow::Error> = None;
        let mut session_opened = false;

        for attempt in 0..=SESSION_OPEN_RETRIES {
            match UploadSession::open(&file_hash_full) {
                Ok(existing_session) => {
                    let published = existing_session.get_published_count()?;
                    let total = existing_session.total_chunks;
                    drop(existing_session); // Release the lock

                    print!(
                        "Resume interrupted upload? ({}/{} chunks done) [Y/n] ",
                        published, total
                    );
                    io::stdout().flush()?;

                    let mut input = String::new();
                    io::stdin().read_line(&mut input)?;

                    let input = input.trim().to_lowercase();
                    if input.is_empty() || input == "y" || input == "yes" {
                        resuming = true;
                    } else {
                        println!("Starting fresh upload...");
                        UploadSession::delete(&file_hash_full)?;
                    }
                    session_opened = true;
                    break;
                }
                Err(e) => {
                    // Check if error is transient and worth retrying
                    if is_transient_error(&e) && attempt < SESSION_OPEN_RETRIES {
                        if verbose {
                            eprintln!(
                                "Session open failed (attempt {}/{}): {}",
                                attempt + 1,
                                SESSION_OPEN_RETRIES + 1,
                                e
                            );
                            eprintln!("Retrying in {}ms...", SESSION_RETRY_DELAY_MS);
                        }
                        std::thread::sleep(Duration::from_millis(SESSION_RETRY_DELAY_MS));
                        last_error = Some(e);
                        continue;
                    }
                    last_error = Some(e);
                    break;
                }
            }
        }

        // Handle session open failure after retries
        if !session_opened {
            if let Some(e) = last_error {
                eprintln!("Error: Could not open existing session after {} attempts", SESSION_OPEN_RETRIES + 1);
                eprintln!("Details: {}", e);
                eprintln!("Full error chain: {:?}", e);

                // Check if this is a corruption error that requires deletion
                if is_corruption_error(&e) {
                    eprintln!("\nThe session database appears to be corrupted or incompatible.");

                    if force {
                        eprintln!("--force specified, deleting corrupted session...");
                        UploadSession::delete(&file_hash_full)?;
                    } else {
                        print!("Delete corrupted session and start fresh? [y/N] ");
                        io::stdout().flush()?;

                        let mut input = String::new();
                        io::stdin().read_line(&mut input)?;

                        let input = input.trim().to_lowercase();
                        if input == "y" || input == "yes" {
                            println!("Deleting corrupted session...");
                            UploadSession::delete(&file_hash_full)?;
                        } else {
                            return Err(anyhow::anyhow!(
                                "Session corrupted. Use --force to delete, or manually remove the session file."
                            ));
                        }
                    }
                } else {
                    // Non-corruption error after retries exhausted
                    return Err(anyhow::anyhow!(
                        "Failed to open session after {} retries: {}. \
                         If another process is using this session, wait and retry. \
                         Use --force to delete the session and start fresh.",
                        SESSION_OPEN_RETRIES + 1,
                        e
                    ));
                }
            }
        }
    }

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

    // 6. Create or resume upload session
    let session = if resuming {
        UploadSession::open(&file_hash_full)?
    } else {
        let meta = UploadMeta {
            file_path: file.clone(),
            file_hash: file_hash.clone(),
            file_hash_full: file_hash_full.clone(),
            file_size,
            chunk_size,
            total_chunks: chunks.len(),
            pubkey: keys.public_key().to_bech32()?,
            encryption,
            relays: data_relays.clone(),
        };
        UploadSession::create(meta)?
    };

    // Get chunks that still need to be published
    let unpublished: HashSet<usize> = session.get_unpublished_indices()?.into_iter().collect();
    let already_published = chunks.len() - unpublished.len();

    if already_published > 0 {
        println!(
            "Resuming: {}/{} chunks already published",
            already_published,
            chunks.len()
        );
    }

    // 7. Publish chunks with progress
    println!("\nUploading {} chunks...", chunks.len());
    let pb = ProgressBar::new(chunks.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} chunks ({eta})")?
            .progress_chars("#>-"),
    );

    // Set progress to already published count
    pb.set_position(already_published as u64);

    for chunk in &chunks {
        // Skip already published chunks
        if !unpublished.contains(&chunk.index) {
            continue;
        }
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
                    // Record in session for resumability
                    session.mark_chunk_published(chunk.index, &event_id, &chunk.hash)?;
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

    // 8. Build manifest from session data
    for (index, event_id, hash) in session.get_published_chunks()? {
        manifest.add_chunk(index, event_id, hash)?;
    }

    // 9. Publish manifest to data relays
    println!("\nPublishing manifest to data relays...");
    let manifest_event = create_manifest_event(&manifest)?;
    match client.send_event_builder(manifest_event.clone()).await {
        Ok(_) => {}
        Err(e) => {
            return Err(anyhow::anyhow!("Failed to publish manifest: {}", e));
        }
    };

    // 7b. Also publish file index to data relays for redundancy
    println!("Publishing file index to data relays...");
    let entry = FileIndexEntry::new(
        file_hash.clone(),
        file_name.clone(),
        file_size,
        manifest.created_at,
        encryption,
    )?;
    if let Err(e) = publish_file_index_to_relays(&client, &keys, entry.clone(), verbose).await {
        eprintln!("  Warning: Failed to publish file index to data relays: {}", e);
    }

    client.disconnect().await;

    // 8. Publish manifest and update file index on index relays
    println!("Publishing to index relays...");
    let manifest_event_id = publish_to_index_relays(
        &keys,
        &index_relays,
        manifest_event,
        entry,
        verbose,
    )
    .await?;

    // 9. Save manifest locally as backup
    let manifest_path = output.unwrap_or_else(|| PathBuf::from(format!("{}.nostrsave", file_name)));
    manifest.save_to_file(&manifest_path)?;

    // Clean up session on success
    session.cleanup()?;

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
async fn publish_to_index_relays(
    keys: &Keys,
    index_relays: &[String],
    manifest_event: EventBuilder,
    entry: FileIndexEntry,
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

    // 3. Update file index on index relays
    publish_file_index_to_relays(&client, keys, entry, verbose).await?;

    client.disconnect().await;
    Ok(manifest_event_id)
}

/// Publish file index to connected relays (used for both data and index relays)
async fn publish_file_index_to_relays(
    client: &Client,
    keys: &Keys,
    entry: FileIndexEntry,
    verbose: bool,
) -> anyhow::Result<()> {
    // Fetch existing file index
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
            if verbose {
                eprintln!("  Failed to fetch existing index: {}", e);
            }
            FileIndex::new()
        }
    };

    // Add entry and publish
    index.add_entry(entry);

    let event_builder = create_file_index_event(&index)?;
    client.send_event_builder(event_builder).await?;

    if verbose {
        println!("  Index updated with {} files", index.len());
    }

    Ok(())
}
