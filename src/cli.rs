use clap::{ArgGroup, Parser, Subcommand};
use std::path::PathBuf;

/// Minimum chunk size (1 KB)
const MIN_CHUNK_SIZE: usize = 1024;
/// Maximum chunk size (1 MB)
const MAX_CHUNK_SIZE: usize = 1_048_576;

/// Parse and validate chunk size within allowed bounds
fn parse_chunk_size(s: &str) -> Result<usize, String> {
    let value: usize = s.parse().map_err(|_| format!("'{}' is not a valid number", s))?;

    if value < MIN_CHUNK_SIZE {
        return Err(format!(
            "chunk size must be at least {} bytes (1 KB), got {}",
            MIN_CHUNK_SIZE, value
        ));
    }
    if value > MAX_CHUNK_SIZE {
        return Err(format!(
            "chunk size must be at most {} bytes (1 MB), got {}",
            MAX_CHUNK_SIZE, value
        ));
    }

    Ok(value)
}

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

        /// Chunk size in bytes (1KB-1MB, default: 64KB)
        #[arg(short, long, default_value = "65536", value_parser = parse_chunk_size)]
        chunk_size: usize,

        /// Output manifest file path (defaults to <filename>.nostrsave)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Download a file from Nostr relays
    #[command(group(ArgGroup::new("input").required(true).args(["manifest", "hash"])))]
    Download {
        /// Path to local manifest file
        #[arg(value_name = "MANIFEST", group = "input")]
        manifest: Option<PathBuf>,

        /// File hash to fetch manifest from relays (e.g., sha256:abc123...)
        #[arg(long, group = "input")]
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

    /// Discover and test Nostr relays
    DiscoverRelays {
        /// Output file for relay discovery results (JSON)
        #[arg(short, long, default_value = "relays.json")]
        output: PathBuf,

        /// Only test configured relays, skip public discovery
        #[arg(long)]
        configured_only: bool,

        /// Connection timeout in seconds
        #[arg(long, default_value = "10")]
        timeout: u64,

        /// Maximum concurrent relay tests
        #[arg(long, default_value = "20")]
        concurrent: usize,

        /// Chunk size in bytes for round-trip test (default: 64KB)
        #[arg(long, default_value = "65536", value_parser = parse_chunk_size)]
        chunk_size: usize,
    },

    /// List files in your Nostr file index
    List {
        /// Public key to list files for (defaults to your key)
        #[arg(long)]
        pubkey: Option<String>,
    },

    /// Print best relays from discovery results in TOML format
    BestRelays {
        /// Path to relay discovery JSON file
        #[arg(default_value = "relays.json")]
        input: PathBuf,

        /// Number of relays to output (default: 10)
        #[arg(short, long, default_value = "10")]
        count: usize,
    },
}
