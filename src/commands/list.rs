use crate::config::{get_data_relays, get_index_relays, get_private_key};
use crate::nostr::{
    create_archive_filter, create_current_index_filter, page_to_archive_number,
    parse_file_index_event,
};
use chrono::{TimeZone, Utc};
use nostr_sdk::prelude::*;
use std::time::Duration;

pub async fn execute(pubkey: Option<&str>, key_file: Option<&str>, from_data_relays: bool, page: u32, verbose: bool) -> anyhow::Result<()> {
    // Validate page number
    if page == 0 {
        return Err(anyhow::anyhow!("Invalid page: must be >= 1"));
    }

    // 1. Determine which public key to query
    let target_pubkey = if let Some(pk) = pubkey {
        // User specified a public key
        PublicKey::parse(pk)?
    } else {
        // Try to get from key_file or config
        match get_private_key(key_file) {
            Ok(private_key) => {
                let keys = Keys::parse(&private_key)?;
                keys.public_key()
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "No --pubkey specified and no identity configured.\n\
                     Use --pubkey <npub/hex> or configure [identity] in config.\n\
                     Underlying error: {}",
                    e
                ));
            }
        }
    };

    if verbose {
        println!("Querying file index for: {}", target_pubkey.to_bech32()?);
    }

    // 2. Setup client and connect to relays
    let relay_list = if from_data_relays {
        println!("Using data relays for file index lookup...");
        get_data_relays()?
    } else {
        get_index_relays()
    };

    println!("Connecting to {} relays...", relay_list.len());

    let keys = Keys::generate(); // Just for client, not signing
    let client = Client::new(keys);

    let mut added_count = 0;
    for relay in &relay_list {
        match client.add_relay(relay).await {
            Ok(_) => added_count += 1,
            Err(e) => {
                if verbose {
                    eprintln!("  Failed to add relay {}: {}", relay, e);
                }
            }
        }
    }

    if added_count == 0 {
        return Err(anyhow::anyhow!(
            "No relays could be added. Check relay URLs in config."
        ));
    }

    client.connect().await;
    client.wait_for_connection(Duration::from_secs(5)).await;

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
            "No relays connected. Added {} relays but none established connection.\n\
             Check your network connection or try different relays.",
            added_count
        ));
    }

    if verbose {
        println!(
            "Connected to {}/{} relays",
            connected_relays.len(),
            added_count
        );
        for relay in &connected_relays {
            println!("  Connected: {}", relay);
        }
    }

    // 3. Fetch file index
    // Always fetch current index first to get total_archives
    println!("Fetching current index...");

    let current_filter = create_current_index_filter(&target_pubkey);
    let current_index = match client.fetch_events(current_filter, Duration::from_secs(10)).await {
        Ok(events) => {
            if let Some(event) = events.iter().max_by_key(|e| e.created_at) {
                Some(parse_file_index_event(event)?)
            } else {
                None
            }
        }
        Err(e) => {
            client.disconnect().await;
            return Err(anyhow::anyhow!("Failed to fetch file index: {}", e));
        }
    };

    // If no current index exists
    let Some(current_index) = current_index else {
        client.disconnect().await;
        if page == 1 {
            println!("No file index found for this public key.");
            println!("\nUpload files with 'nostrsave upload <file>' to create an index.");
        } else {
            println!("Page {} does not exist (no index found).", page);
            println!("\nUse --page 1 to view the most recent files, or omit --page.");
        }
        return Ok(());
    };

    // Now fetch the requested page
    let index = if page == 1 {
        // Page 1 is the current index we already have
        current_index
    } else {
        // Need to fetch an archive
        let total_archives = current_index.total_archives();

        match page_to_archive_number(page, total_archives) {
            Some(archive_number) => {
                println!("Fetching archive page {} (archive {})...", page, archive_number);
                let archive_filter = create_archive_filter(&target_pubkey, archive_number);
                match client.fetch_events(archive_filter, Duration::from_secs(10)).await {
                    Ok(events) => {
                        if let Some(event) = events.iter().max_by_key(|e| e.created_at) {
                            parse_file_index_event(event)?
                        } else {
                            client.disconnect().await;
                            println!("Page {} (archive {}) not found on relays.", page, archive_number);
                            println!("\nThe archive may have been deleted. Use --page 1 for recent files.");
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        client.disconnect().await;
                        return Err(anyhow::anyhow!("Failed to fetch archive: {}", e));
                    }
                }
            }
            None => {
                client.disconnect().await;
                println!(
                    "Page {} does not exist. Total pages: {}",
                    page,
                    current_index.total_pages()
                );
                println!("\nUse --page 1 to view the most recent files, or omit --page.");
                return Ok(());
            }
        }
    };

    client.disconnect().await;

    // 4. Display results
    if index.is_empty() {
        println!("File index is empty.");
        println!("\nUpload files with 'nostrsave upload <file>' to add entries.");
        return Ok(());
    }

    // Show page info
    println!(
        "Page {}/{} ({} files on this page):\n",
        index.page(),
        index.total_pages(),
        index.len()
    );
    println!(
        "  {:<3} {:<35} {:>12}  {:<20}  {:<5}  Hash",
        "#", "Name", "Size", "Uploaded", "Enc"
    );
    println!("  {}", "-".repeat(105));

    for (i, entry) in index.entries().iter().enumerate() {
        let size_str = format_size(entry.file_size());
        let date_str = format_timestamp(entry.uploaded_at());
        let enc_str = entry.encryption().to_string();
        let hash_short = if entry.file_hash().chars().count() > 20 {
            format!("{}...", entry.file_hash().chars().take(20).collect::<String>())
        } else {
            entry.file_hash().to_string()
        };

        // Truncate filename if too long
        let name = if entry.file_name().chars().count() > 35 {
            format!("{}...", entry.file_name().chars().take(32).collect::<String>())
        } else {
            entry.file_name().to_string()
        };

        println!(
            "  {:<3} {:<35} {:>12}  {:<20}  {:<5}  {}",
            i + 1,
            name,
            size_str,
            date_str,
            enc_str,
            hash_short
        );
    }

    // Always show full hashes for easy copying
    println!("\nHashes:");
    for (i, entry) in index.entries().iter().enumerate() {
        println!("  #{}: {}", i + 1, entry.file_hash());
    }

    println!("\nDownload with: nostrsave download <hash>");

    // Show pagination hints
    if index.total_pages() > 1 {
        println!();
        if index.page() < index.total_pages() {
            println!(
                "Use --page {} to view older files",
                index.page() + 1
            );
        }
        if index.page() > 1 {
            println!(
                "Use --page {} to view newer files",
                index.page() - 1
            );
        }
    }

    Ok(())
}

/// Format file size in human-readable format
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format Unix timestamp as human-readable date
fn format_timestamp(ts: u64) -> String {
    match Utc.timestamp_opt(ts as i64, 0) {
        chrono::LocalResult::Single(dt) => dt.format("%Y-%m-%d %H:%M").to_string(),
        _ => "Unknown".to_string(),
    }
}
