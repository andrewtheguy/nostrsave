use crate::cli_parsers::{
    parse_chunk_size, parse_encryption, parse_event_id, parse_file_hash, parse_relay_url,
};
use crate::config::EncryptionAlgorithm;
use clap::{Parser, Subcommand, ValueEnum};
use nostr_sdk::EventId;
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

        /// Encryption algorithm: aes256gcm (default), nip44, or none
        #[arg(short, long, value_parser = parse_encryption)]
        encryption: Option<EncryptionAlgorithm>,

        /// Force delete corrupted session without prompting
        #[arg(long)]
        force: bool,
    },

    /// Download a file from Nostr relays
    Download {
        /// File hash to fetch manifest from relays (sha256:<hash> or raw 64-hex)
        #[arg(value_name = "HASH", required_unless_present = "manifest", value_parser = parse_file_hash)]
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

    /// Show public key from private key file, default to the key file path from ~/.config/nostrsave/config.toml
    Pubkey,

    /// Discover and test Nostr relays
    DiscoverRelays {
        /// Single relay URL to test (e.g., wss://relay.example.com)
        #[arg(value_name = "RELAY", required_unless_present = "relay_source", value_parser = parse_relay_url)]
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

    /// Inspect a specific Nostr event on a relay
    InspectEvent {
        /// Relay URL to query (e.g., wss://relay.example.com)
        #[arg(value_name = "RELAY", value_parser = parse_relay_url)]
        relay: String,

        /// Event ID (64-hex)
        #[arg(value_name = "EVENT_ID", value_parser = parse_event_id)]
        event_id: EventId,

        /// Attempt to decrypt chunk payloads (requires key file / config)
        #[arg(long)]
        decrypt: bool,
    },
}
