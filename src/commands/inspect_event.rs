use crate::config::get_private_key;
use crate::nostr::parse_chunk_event;
use nostr_sdk::prelude::*;
use std::time::Duration;

const CONTENT_PREVIEW_BYTES: usize = 256;

fn hex_preview(bytes: &[u8]) -> String {
    let end = bytes.len().min(CONTENT_PREVIEW_BYTES);
    let mut out = String::with_capacity(end * 2);
    for b in &bytes[..end] {
        out.push_str(&format!("{:02x}", b));
    }
    if bytes.len() > end {
        out.push_str("...");
    }
    out
}

fn utf8_preview(bytes: &[u8]) -> Option<String> {
    std::str::from_utf8(bytes).ok().map(|s| {
        let end = s.len().min(CONTENT_PREVIEW_BYTES);
        let mut out = s[..end].to_string();
        if s.len() > end {
            out.push_str("...");
        }
        out
    })
}

fn encryption_tag(event: &Event) -> Option<String> {
    event
        .tags
        .iter()
        .find(|t| t.kind() == TagKind::custom("encryption"))
        .and_then(|t| t.as_slice().get(1))
        .map(|s| s.to_string())
}

pub async fn execute(
    relay: String,
    event_id: EventId,
    decrypt: bool,
    key_file: Option<&str>,
    verbose: bool,
) -> anyhow::Result<()> {
    let keys = Keys::generate(); // anonymous client for fetching
    let client = Client::new(keys);

    client.add_relay(&relay).await?;
    client.connect().await;
    client.wait_for_connection(Duration::from_secs(10)).await;

    let filter = Filter::new().id(event_id);
    let events = client.fetch_events(filter, Duration::from_secs(10)).await?;

    let event = events
        .first()
        .ok_or_else(|| anyhow::anyhow!("Event not found on relay {}", relay))?;

    println!("Event ID: {}", event.id);
    println!("Kind: {}", event.kind);
    println!("Author: {}", event.pubkey);
    println!("Created at: {}", event.created_at);
    if let Some(enc) = encryption_tag(event) {
        println!("Encryption tag: {}", enc);
    }
    println!("Content length: {}", event.content.len());

    if verbose {
        let json = serde_json::to_string_pretty(event)?;
        println!("\nFull event JSON:\n{}", json);
    } else {
        println!("\nContent (as stored):");
        println!("{}", event.content);
    }

    // Attempt to decode chunk payloads (kind 30078)
    if event.kind == Kind::Custom(crate::config::CHUNK_EVENT_KIND) {
        let decrypt_keys = if decrypt {
            let private_key = get_private_key(key_file)?;
            Some(Keys::parse(&private_key)?)
        } else {
            None
        };

        match parse_chunk_event(event, decrypt_keys.as_ref()) {
            Ok(decoded) => {
                println!("\nDecoded chunk index: {}", decoded.index);
                println!("Decoded bytes length: {}", decoded.data.len());
                println!("Decoded bytes (hex preview): {}", hex_preview(&decoded.data));
                if let Some(text) = utf8_preview(&decoded.data) {
                    println!("Decoded bytes (utf8 preview): {}", text);
                }
            }
            Err(e) => {
                println!("\nDecoded payload unavailable: {}", e);
                if !decrypt {
                    println!("Hint: use --decrypt to attempt decryption (requires key file).");
                }
            }
        }
    }

    Ok(())
}
