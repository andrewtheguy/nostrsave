use crate::config::EncryptionAlgorithm;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Source for relay discovery
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum RelaySource {
    /// Only test configured relays
    ConfiguredOnly,
    /// Discover from nostr.watch + configured relays
    Nostrwatch,
    /// Discover from NIP-65 relay list events on index relays
    IndexRelays,
}

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

        /// Save manifest locally to this path (not saved by default)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Encryption algorithm: nip44 (default) or none
        #[arg(short, long, value_parser = parse_encryption)]
        encryption: Option<EncryptionAlgorithm>,

        /// Force delete corrupted session without prompting
        #[arg(long)]
        force: bool,
    },

    /// Download a file from Nostr relays
    Download {
        /// File hash to fetch manifest from relays (e.g., sha256:abc123...)
        #[arg(value_name = "HASH", required_unless_present = "manifest")]
        hash: Option<String>,

        /// Load manifest from local file instead of fetching by hash
        #[arg(short, long, conflicts_with = "hash")]
        manifest: Option<PathBuf>,

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
        /// Single relay URL to test (e.g., wss://relay.example.com)
        #[arg(value_name = "RELAY", required_unless_present = "relay_source")]
        relay: Option<String>,

        /// Relay source for discovery: "configured-only", "nostrwatch", or "index-relays"
        #[arg(long, value_name = "SOURCE", conflicts_with = "relay")]
        relay_source: Option<RelaySource>,

        /// Output file for relay discovery results (JSON)
        #[arg(short, long, default_value = "relays.json")]
        output: PathBuf,

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

        /// Page number (1 = current index; higher pages map to archives)
        #[arg(long, default_value = "1")]
        page: u32,
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
