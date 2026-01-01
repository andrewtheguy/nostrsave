mod chunking;
mod cli;
mod commands;
mod config;
mod error;
mod manifest;
mod nostr;

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
            commands::upload::execute(
                file,
                chunk_size,
                output,
                cli.private_key,
                cli.relay,
                cli.verbose,
            )
            .await?;
        }
        Commands::Download {
            manifest,
            output,
            stats,
        } => {
            commands::download::execute(
                manifest,
                output,
                stats,
                cli.private_key,
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
            println!("Use -k <nsec> to specify your key when uploading.");
        }
    }

    Ok(())
}
