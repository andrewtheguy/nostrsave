use crate::config::EncryptionAlgorithm;
use clap::{ArgGroup, Parser, Subcommand};
use std::path::PathBuf;

/// Minimum chunk size (1 KB)
const MIN_CHUNK_SIZE: usize = 1024;
/// Maximum chunk size (65408 bytes - tested limit for reliable relay storage; NIP-44 allows up to 65535)
const MAX_CHUNK_SIZE: usize = 65408;

/// Parse encryption algorithm from string
fn parse_encryption(s: &str) -> Result<EncryptionAlgorithm, String> {
    s.parse::<EncryptionAlgorithm>()
}

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
            "chunk size must be at most {} bytes, got {}",
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

    /// Verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Path to key file (overrides config)
    #[arg(short, long, global = true)]
    pub key_file: Option<String>,

    /// Public key (npub or hex) for read-only operations
    #[arg(short, long, global = true)]
    pub pubkey: Option<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Upload a file to Nostr relays
    Upload {
        /// Path to the file to upload
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Chunk size in bytes (1KB-65408 tested max, default: 32KB)
        #[arg(short, long, default_value = "32768", value_parser = parse_chunk_size)]
        chunk_size: usize,

        /// Output manifest file path (defaults to <filename>.nostrsave)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Encryption algorithm: nip44 (default) or none
        #[arg(short, long, value_parser = parse_encryption)]
        encryption: Option<EncryptionAlgorithm>,
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

        /// Fetch manifest from data relays instead of index relays
        #[arg(long)]
        from_data_relays: bool,
    },

    /// Generate a new Nostr keypair
    Keygen,

    /// Show public key from config
    Pubkey,

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

        /// Chunk size in bytes for round-trip test (default: 32KB)
        #[arg(long, default_value = "32768", value_parser = parse_chunk_size)]
        chunk_size: usize,
    },

    /// List files in your Nostr file index
    List {
        /// Fetch file index from data relays instead of index relays
        #[arg(long)]
        from_data_relays: bool,
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
