mod chunking;
mod cli;
mod commands;
mod config;
mod error;
mod manifest;
mod nostr;
mod relay;

use std::path::Path;

use clap::Parser;
use cli::{Cli, Commands};
use nostr_sdk::ToBech32;

/// Load private key from file or use provided key
fn resolve_private_key(
    private_key: Option<String>,
    key_file: Option<&Path>,
) -> anyhow::Result<Option<String>> {
    if let Some(path) = key_file {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read key file '{}': {}", path.display(), e))?;
        let key = content.trim().to_string();
        if key.is_empty() {
            return Err(anyhow::anyhow!("Key file is empty: {}", path.display()));
        }
        Ok(Some(key))
    } else {
        Ok(private_key)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Resolve private key from file or CLI argument
    let private_key = resolve_private_key(cli.private_key, cli.key_file.as_deref())?;

    match cli.command {
        Commands::Upload {
            file,
            chunk_size,
            output,
        } => {
            commands::upload::execute(
                file,
                chunk_size,
                output,
                private_key,
                cli.relay,
                cli.verbose,
            )
            .await?;
        }
        Commands::Download {
            manifest,
            hash,
            output,
            stats,
        } => {
            commands::download::execute(
                manifest,
                hash,
                output,
                stats,
                private_key,
                cli.relay,
                cli.verbose,
            )
            .await?;
        }
        Commands::Keygen => {
            let keys = nostr_sdk::Keys::generate();
            println!("Generated new Nostr keypair:");
            println!();
            println!("  Public key (npub):  {}", keys.public_key().to_bech32()?);
            println!("  Private key (nsec): {}", keys.secret_key().to_bech32()?);
            println!();
            println!("Save your private key securely!");
            println!("Use -k <nsec> or --key-file <path> to specify your key when uploading.");
        }
        Commands::DiscoverRelays {
            output,
            configured_only,
            timeout,
            concurrent,
            chunk_size,
        } => {
            commands::discover_relays::execute(output, configured_only, timeout, concurrent, chunk_size, cli.verbose)
                .await?;
        }
        Commands::List { pubkey } => {
            commands::list::execute(pubkey, private_key, cli.relay, cli.verbose).await?;
        }
    }

    Ok(())
}
