use crate::config::{get_index_relays, get_private_key};
use crate::nostr::{create_file_index_filter, parse_file_index_event};
use chrono::{TimeZone, Utc};
use nostr_sdk::prelude::*;
use std::time::Duration;

pub async fn execute(pubkey: Option<&str>, key_file: Option<&str>, verbose: bool) -> anyhow::Result<()> {
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
            Err(_) => {
                return Err(anyhow::anyhow!(
                    "No --pubkey specified and no identity configured.\n\
                     Use --pubkey <npub/hex> or configure [identity] in config."
                ));
            }
        }
    };

    if verbose {
        println!("Querying file index for: {}", target_pubkey.to_bech32()?);
    }

    // 2. Setup client and connect to index relays (defaults if no config)
    let relay_list = get_index_relays();

    println!("Connecting to {} relays...", relay_list.len());

    let keys = Keys::generate(); // Just for client, not signing
    let client = Client::new(keys);

    for relay in &relay_list {
        if let Err(e) = client.add_relay(relay).await {
            if verbose {
                eprintln!("  Failed to add relay {}: {}", relay, e);
            }
        }
    }

    client.connect().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 3. Fetch file index
    println!("Fetching file index...\n");
    let filter = create_file_index_filter(&target_pubkey);

    let index = match client.fetch_events(filter, Duration::from_secs(10)).await {
        Ok(events) => {
            if let Some(event) = events.iter().next() {
                parse_file_index_event(event)?
            } else {
                println!("No file index found for this public key.");
                println!("\nUpload files with 'nostrsave upload <file>' to create an index.");
                client.disconnect().await;
                return Ok(());
            }
        }
        Err(e) => {
            client.disconnect().await;
            return Err(anyhow::anyhow!("Failed to fetch file index: {}", e));
        }
    };

    client.disconnect().await;

    // 4. Display results
    if index.is_empty() {
        println!("File index is empty.");
        println!("\nUpload files with 'nostrsave upload <file>' to add entries.");
        return Ok(());
    }

    println!("Indexed files ({}):\n", index.len());
    println!(
        "  {:<3} {:<35} {:>12}  {:<20}  {:<5}  Hash",
        "#", "Name", "Size", "Uploaded", "Enc"
    );
    println!("  {}", "-".repeat(105));

    for (i, entry) in index.entries.iter().enumerate() {
        let size_str = format_size(entry.file_size);
        let date_str = format_timestamp(entry.uploaded_at);
        let enc_str = if entry.encrypted { "yes" } else { "no" };
        let hash_short = if entry.file_hash.len() > 20 {
            format!("{}...", &entry.file_hash[..20])
        } else {
            entry.file_hash.clone()
        };

        // Truncate filename if too long
        let name = if entry.file_name.len() > 35 {
            format!("{}...", &entry.file_name[..32])
        } else {
            entry.file_name.clone()
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
    for (i, entry) in index.entries.iter().enumerate() {
        println!("  #{}: {}", i + 1, entry.file_hash);
    }

    println!("\nDownload with: nostrsave download --hash <hash>");

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
