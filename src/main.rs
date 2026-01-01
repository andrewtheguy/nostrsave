mod chunking;
mod cli;
mod commands;
mod config;
mod error;
mod manifest;
mod nostr;
mod relay;

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
        } => {
            commands::upload::execute(file, chunk_size, output, cli.key_file.as_deref(), cli.verbose).await?;
        }
        Commands::Download {
            manifest,
            hash,
            output,
            stats,
        } => {
            commands::download::execute(manifest, hash, output, stats, cli.verbose).await?;
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
        Commands::List => {
            commands::list::execute(cli.pubkey.as_deref(), cli.key_file.as_deref(), cli.verbose).await?;
        }
        Commands::BestRelays { input, count } => {
            commands::best_relays::execute(input, count)?;
        }
    }

    Ok(())
}
