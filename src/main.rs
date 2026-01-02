mod chunking;
mod cli;
mod commands;
mod config;
mod crypto;
mod error;
mod manifest;
mod nostr;
mod relay;
mod session;

use clap::Parser;
use cli::{Cli, Commands};
use nostr_sdk::ToBech32;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Upload {
            file,
            chunk_size,
            output,
            encryption,
            force,
        } => {
            // CLI flag takes precedence, then config, then default
            let encryption = encryption.unwrap_or_else(config::get_encryption_algorithm);
            commands::upload::execute(file, chunk_size, output, cli.key_file.as_deref(), encryption, force, cli.verbose).await?;
        }
        Commands::Download {
            manifest,
            hash,
            output,
            stats,
            from_data_relays,
        } => {
            commands::download::execute(manifest, hash, output, cli.key_file.as_deref(), stats, from_data_relays, cli.verbose).await?;
        }
        Commands::Keygen => {
            let keys = nostr_sdk::Keys::generate();
            println!("Generated new Nostr keypair:");
            println!();
            println!("  Public key (npub):  {}", keys.public_key().to_bech32()?);
            println!("  Private key (nsec): {}", keys.secret_key().to_bech32()?);
            println!();
            println!("Save your private key securely!");
            println!("Add to config.toml [identity] section.");
        }
        Commands::Pubkey => {
            let private_key = config::get_private_key(cli.key_file.as_deref())?;
            let keys = nostr_sdk::Keys::parse(&private_key)?;
            println!("{}", keys.public_key().to_bech32()?);
        }
        Commands::DiscoverRelays {
            output,
            configured_only,
            timeout,
            concurrent,
            chunk_size,
        } => {
            commands::discover_relays::execute(
                output,
                configured_only,
                timeout,
                concurrent,
                chunk_size,
                cli.verbose,
            )
            .await?;
        }
        Commands::List { from_data_relays } => {
            commands::list::execute(cli.pubkey.as_deref(), cli.key_file.as_deref(), from_data_relays, cli.verbose).await?;
        }
        Commands::BestRelays { input, count } => {
            commands::best_relays::execute(input, count)?;
        }
    }

    Ok(())
}
