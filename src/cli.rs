use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "nostrsave")]
#[command(about = "Store and retrieve files on Nostr", long_about = None)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Private key (hex or nsec)
    #[arg(short = 'k', long, global = true, conflicts_with = "key_file")]
    pub private_key: Option<String>,

    /// Path to file containing private key (hex or nsec)
    #[arg(long, global = true, conflicts_with = "private_key")]
    pub key_file: Option<PathBuf>,

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
        /// Path to local manifest file
        #[arg(value_name = "MANIFEST", conflicts_with = "hash")]
        manifest: Option<PathBuf>,

        /// File hash to fetch manifest from relays (e.g., sha256:abc123...)
        #[arg(long, conflicts_with = "manifest")]
        hash: Option<String>,

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
