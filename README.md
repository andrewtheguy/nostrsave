# nostrsave

A CLI tool for storing and retrieving files on the Nostr network.

## Features

- **AES-256-GCM encryption** enabled by default (key derived from Nostr private key)
- **NIP-44 encryption** supported as optional mode
- **Resumable uploads/downloads** with SQLite-based session tracking
- **Upload files** to Nostr relays as chunked events
- **Download files** using file hash or local manifest
- **File index** automatically maintained on your public key
- **Relay discovery** with round-trip testing
- **TOML configuration** with key file support

## Disclaimer

**Hobby project:** This is a hobby project. No backward compatibility is expected between versions.

**Long-term storage is not guaranteed.** File persistence depends entirely on the Nostr relays you use. Relays may delete data at any time, go offline, or impose storage limits. Always keep local backups of important files. This tool is best suited for short term file sharing or as a temporary storage solution, not as a primary storage solution or for backup purposes.

## Installation

Quick install (Linux/macOS):

```bash
curl -fsSL https://andrewtheguy.github.io/nostrsave/install.sh | bash
```

Build from source:

```bash
cargo build --release
```

## Quick Start

### 1. Setup (one time)

```bash
# Generate a keypair
nostrsave keygen

# Save the private key (replace with the nsec from keygen)
mkdir -p ~/.config/nostrsave
echo "nsec1..." > ~/.config/nostrsave/nostr.key
chmod 600 ~/.config/nostrsave/nostr.key

# Create config with the sample (uses key from ~/.config/nostrsave/nostr.key)
mkdir -p ~/.config/nostrsave
cp config.sample.toml ~/.config/nostrsave/config.toml
```

### 2. Usage

```bash
# Upload a file (encrypted by default with aes256gcm)
nostrsave upload photo.jpg

# List your indexed files
nostrsave list

# Download a file by hash (decrypts automatically)
nostrsave download abc123...
# (also accepts sha256:<hash>)

# Upload without encryption
nostrsave upload photo.jpg --encryption none
```

### Without config file

You can also use command-line flags directly:

```bash
nostrsave upload photo.jpg --key-file ~/.config/nostrsave/nostr.key
nostrsave list --key-file ~/.config/nostrsave/nostr.key
```

## Configuration

Copy the sample config and edit:

```bash
mkdir -p ~/.config/nostrsave
cp config.sample.toml ~/.config/nostrsave/config.toml
```

Or create `~/.config/nostrsave/config.toml`:

```toml
[identity]
# Key file path (supports ~ expansion)
key_file = "~/.config/nostrsave/nostr.key"

[data_relays]
# Where to get data relays from:
# - "config" (default): use the hard-coded urls below
# - "discovered": use relays saved by `nostrsave discover-relays` (stored alongside your config.toml as `data_relays.sqlite3`)
source = "config"

# `batch_size` is only used when `source = "discovered"` (ignored for `source = "config"`). It controls how many relays are selected/used per upload operation.
# Default: 6. Recommended: 1–32 (larger values can increase throughput, but use more CPU/memory and open more connections).
batch_size = 6

# Relays for storing file chunks (need write access)
urls = [
    "wss://relay.damus.io",
    "wss://nos.lol",
]

[index_relays]
# Relays for manifest and file index (public discovery)
urls = [
    "wss://relay.damus.io",
    "wss://nos.lol",
]

[encryption]
# Default encryption algorithm: "aes256gcm" (default), "nip44", or "none"
algorithm = "aes256gcm"
```

### Configuration Priority

1. CLI flags (`--key-file`, `--encryption`)
2. TOML config (`config.toml`)
3. Built-in defaults (aes256gcm encryption, fallback relays for index)

## Commands

### upload

Upload a file to Nostr relays. Files are encrypted by default using AES-256-GCM.

```bash
nostrsave upload <FILE> [OPTIONS]

Options:
  -c, --chunk-size <BYTES>       Chunk size (1KB-65408 tested max, default: 32KB)
  -o, --output <PATH>            Save manifest locally to this path (not saved by default)
  -e, --encryption <ALGORITHM>   Encryption: aes256gcm (default), nip44, or none
  -f, --force                    Force delete corrupted session without prompting
  -v, --verbose                  Verbose output
```

Uploads automatically resume from the last successful chunk if interrupted. Session data is stored in a temporary SQLite database.

### download

Download a file from Nostr relays. Encrypted files are automatically decrypted.

```bash
nostrsave download <HASH> [OPTIONS]
nostrsave download --manifest <PATH> [OPTIONS]

Options:
  -m, --manifest <PATH>  Load manifest from local file instead of fetching by hash
  -o, --output <PATH>    Output file path
  --stats                Show relay statistics
  -v, --verbose          Verbose output
```

Downloads automatically resume from the last successful chunk if interrupted. Session data is stored in a temporary SQLite database.

### list

List files in your Nostr file index.

```bash
nostrsave list [OPTIONS]

Options:
  -p, --pubkey <NPUB>  List files for another user (read-only)
  -v, --verbose        Verbose output
```

### discover-relays

Discover and test Nostr relays.

```bash
# Test a single relay (outputs JSON to stdout)
nostrsave discover-relays wss://relay.example.com

# Discover relays from various sources
nostrsave discover-relays --relay-source <SOURCE>

Sources:
  nostrwatch       Discover from nostr.watch API + configured relays
  configured-only  Discover from configured index relays only
  index-relays     Discover from NIP-66/NIP-65 events on index relays

No authentication required - discovery uses public APIs and anonymous queries.
Relay testing uses a temporary keypair internally.

Options:
  -o, --output <PATH>     Output JSON file (default: relays-{source}.json)
  --timeout <SECONDS>     Connection timeout (default: 10)
  --concurrent <N>        Max concurrent tests (default: 20)
  --chunk-size <BYTES>    Payload size for round-trip test
```

In bulk mode, `discover-relays` also persists the working relays list into `data_relays.sqlite3` in the same directory as your config.toml for use with `data_relays.source = "discovered"`.

### keygen

Generate a new Nostr keypair.

```bash
nostrsave keygen
```

### best-relays

Print top relays from discovery results in TOML format.

```bash
nostrsave best-relays [JSON_FILE] [OPTIONS]

Options:
  -c, --count <N>    Number of relays (default: 10)
```

Example workflow:
```bash
nostrsave discover-relays --relay-source nostrwatch
nostrsave best-relays relays-nostrwatch.json -c 10
# Copy output to your `config.toml` under `[data_relays].urls` (or set `data_relays.source = "discovered"` to use the saved DB).
```

## Resumable Sessions

Uploads and downloads are automatically resumable. If a transfer is interrupted (network failure, Ctrl+C, crash), simply run the same command again to resume from where it left off.

**How it works:**
- Session state is tracked in SQLite databases in your system's temp directory
- Each file gets a unique session identified by its SHA-512 hash
- Upload sessions track which chunks have been published
- Download sessions store received chunks until all are collected
- Sessions are automatically cleaned up on successful completion

**Session files location:** `$TMPDIR/nostrsave-sessions/` (e.g., `/tmp/nostrsave-sessions/`)

**Concurrency protection:** Sessions use OS-level file locks to prevent concurrent access. If you see "Another session is using this file", wait for the other process to complete.

**Corrupted sessions:** If a session becomes corrupted, the upload command will prompt for confirmation before deleting it. Use `--force` to skip the prompt.

## How It Works

Files are split into chunks (default 32KB), encrypted with AES-256-GCM (key derived from your private key), and published as Nostr events. A manifest event ties all chunks together. Manifest and index events are zstd-compressed (level 9) and base85-encoded. An optional file index event tracks all your uploads.

**Encryption:** By default, chunks are encrypted using AES-256-GCM (key derived from your private key). Use `--encryption nip44` for NIP-44 mode (self-encryption) or `--encryption none` to upload unencrypted files.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for technical details.

## Event Kinds

| Kind  | Description |
|-------|-------------|
| 30078 | File chunk (parameterized replaceable) |
| 30079 | File manifest |
| 30080 | File index |

## License

MIT
