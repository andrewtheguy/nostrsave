use crate::chunking::FileChunker;
use crate::config::{get_default_relays, validate_relays};
use crate::manifest::Manifest;
use crate::nostr::{
    create_chunk_event, create_file_index_event, create_file_index_filter, create_manifest_event,
    parse_file_index_event, ChunkMetadata, FileIndex, FileIndexEntry,
};
use indicatif::{ProgressBar, ProgressStyle};
use nostr_sdk::prelude::*;
use std::path::PathBuf;
use std::time::Duration;

pub async fn execute(
    file: PathBuf,
    chunk_size: usize,
    output: Option<PathBuf>,
    private_key: Option<String>,
    relays: Vec<String>,
    verbose: bool,
) -> anyhow::Result<()> {
    // 1. Setup keys - require private key
    let private_key = private_key.ok_or_else(|| {
        anyhow::anyhow!("Private key required. Use -k <nsec> or --key-file <path>")
    })?;
    let keys = Keys::parse(&private_key)?;

    // 2. Verify file exists
    if !file.exists() {
        return Err(anyhow::anyhow!("File not found: {}", file.display()));
    }

    let file_name = file
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Invalid file path"))?
        .to_string_lossy()
        .to_string();
    let file_size = std::fs::metadata(&file)?.len();

    println!("File: {} ({} bytes)", file_name, file_size);

    // 3. Split file into chunks
    println!("Splitting file into chunks...");
    let chunker = FileChunker::new(chunk_size)?;
    let (file_hash, chunks) = chunker.split_file(&file)?;

    println!("File hash: {}", file_hash);
    println!(
        "Created {} chunks of up to {} bytes each",
        chunks.len(),
        chunk_size
    );

    // 4. Setup client and connect to relays
    let relay_list: Vec<String> = if relays.is_empty() {
        get_default_relays()
    } else {
        validate_relays(&relays)
    };

    if relay_list.is_empty() {
        return Err(anyhow::anyhow!("No valid relay URLs provided"));
    }

    println!("\nConnecting to {} relays...", relay_list.len());

    let client = Client::new(keys.clone());
    let mut added_relays = Vec::new();
    for relay in &relay_list {
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

    // Wait a bit for connections to establish
    tokio::time::sleep(Duration::from_secs(2)).await;

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

    // 5. Create manifest
    let mut manifest = Manifest::new(
        file_name.clone(),
        file_hash.clone(),
        file_size,
        chunk_size,
        keys.public_key().to_bech32()?,
        relay_list.clone(),
    );

    // 6. Publish chunks with progress
    println!("\nUploading {} chunks...", chunks.len());
    let pb = ProgressBar::new(chunks.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} chunks ({eta})")?
            .progress_chars("#>-"),
    );

    for chunk in &chunks {
        let metadata = ChunkMetadata {
            file_hash: &file_hash,
            chunk_index: chunk.index,
            total_chunks: manifest.total_chunks,
            chunk_hash: &chunk.hash,
            chunk_data: &chunk.data,
            filename: &file_name,
        };
        let event_builder = create_chunk_event(&metadata)?;

        match client.send_event_builder(event_builder).await {
            Ok(output) => {
                let event_id = output.val.to_bech32()?;
                if verbose {
                    println!("  Chunk {} -> {}", chunk.index, event_id);
                }
                manifest.add_chunk(chunk.index, event_id, chunk.hash.clone())?;
            }
            Err(e) => {
                pb.finish_and_clear();
                return Err(anyhow::anyhow!("Failed to publish chunk {}: {}", chunk.index, e));
            }
        }

        pb.inc(1);
    }

    pb.finish_with_message("Upload complete!");

    // 7. Publish manifest to relays
    println!("\nPublishing manifest...");
    let manifest_event = create_manifest_event(&manifest)?;
    let manifest_event_id = match client.send_event_builder(manifest_event).await {
        Ok(output) => output.val.to_bech32()?,
        Err(e) => {
            return Err(anyhow::anyhow!("Failed to publish manifest: {}", e));
        }
    };

    // 8. Update file index
    println!("Updating file index...");
    let index_updated = update_file_index(
        &client,
        &keys,
        &file_hash,
        &file_name,
        file_size,
        manifest.created_at,
        verbose,
    )
    .await;

    if !index_updated {
        eprintln!("  Warning: Failed to update file index (upload still succeeded)");
    }

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

/// Update the file index with a new entry
async fn update_file_index(
    client: &Client,
    keys: &Keys,
    file_hash: &str,
    file_name: &str,
    file_size: u64,
    uploaded_at: u64,
    verbose: bool,
) -> bool {
    // 1. Try to fetch existing file index
    let filter = create_file_index_filter(&keys.public_key());
    let mut index = match client.fetch_events(filter, Duration::from_secs(10)).await {
        Ok(events) => {
            if let Some(event) = events.iter().next() {
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
                eprintln!("  Failed to fetch index: {}", e);
            }
            FileIndex::new()
        }
    };

    // 2. Add new entry
    let entry = FileIndexEntry {
        file_hash: file_hash.to_string(),
        file_name: file_name.to_string(),
        file_size,
        uploaded_at,
    };
    index.add_entry(entry);

    // 3. Publish updated index
    let event_builder = match create_file_index_event(&index) {
        Ok(builder) => builder,
        Err(e) => {
            if verbose {
                eprintln!("  Failed to create index event: {}", e);
            }
            return false;
        }
    };

    match client.send_event_builder(event_builder).await {
        Ok(_) => {
            if verbose {
                println!("  Index updated with {} files", index.len());
            }
            true
        }
        Err(e) => {
            if verbose {
                eprintln!("  Failed to publish index: {}", e);
            }
            false
        }
    }
}
