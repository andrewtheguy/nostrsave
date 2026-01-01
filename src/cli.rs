use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "nostrsave")]
#[command(about = "Store and retrieve files on Nostr", long_about = None)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Private key (hex or nsec). If not provided, generates new keys
    #[arg(short = 'k', long, global = true)]
    pub private_key: Option<String>,

    /// Relay URLs (can be specified multiple times)
    #[arg(short, long, global = true)]
    pub relay: Vec<String>,

    /// Verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Upload a file to Nostr relays
    Upload {
        /// Path to the file to upload
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Chunk size in bytes (default: 65536 = 64KB)
        #[arg(short, long, default_value = "65536")]
        chunk_size: usize,

        /// Output manifest file path (defaults to <filename>.nostrsave)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Download a file from Nostr relays
    Download {
        /// Path to manifest file
        #[arg(value_name = "MANIFEST")]
        manifest: PathBuf,

        /// Output file path (defaults to original filename)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Show detailed relay statistics
        #[arg(long)]
        stats: bool,
    },

    /// Generate a new Nostr keypair
    Keygen,
}
