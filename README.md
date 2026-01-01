# nostrsave

A CLI tool for storing and retrieving files on the Nostr network.

## Features

- **NIP-44 encryption** enabled by default (self-encrypt to own public key)
- **Upload files** to Nostr relays as chunked events
- **Download files** using file hash or local manifest
- **File index** automatically maintained on your public key
- **Relay discovery** with round-trip testing
- **TOML configuration** with key file support

## Installation

```bash
cargo install --path .
```

## Quick Start

```bash
# Generate a keypair
nostrsave keygen

# Upload a file (encrypted by default)
nostrsave upload photo.jpg --key-file ~/.config/nostrsave/nostr.key

# Upload without encryption
nostrsave upload photo.jpg --key-file nostr.key --no-encrypt

# List your indexed files
nostrsave list --key-file ~/.config/nostrsave/nostr.key

# Download a file by hash (decrypts automatically)
nostrsave download --hash sha256:abc123... --key-file ~/.config/nostrsave/nostr.key
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
# Option 1: Inline key
private_key = "nsec1..."

# Option 2: Key file path (supports ~)
key_file = "~/.config/nostrsave/nostr.key"

[data_relays]
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
```

### Configuration Priority

1. CLI flag (`--key-file`)
2. TOML config (`config.toml`)
3. Built-in fallback relays (for index relays only)

## Commands

### upload

Upload a file to Nostr relays. Files are encrypted by default using NIP-44.

```bash
nostrsave upload <FILE> [OPTIONS]

Options:
  -c, --chunk-size <BYTES>  Chunk size (1KB-65408, default: 65408)
  -o, --output <PATH>       Output manifest file path
  --no-encrypt              Disable NIP-44 encryption
  -v, --verbose             Verbose output
```

### download

Download a file from Nostr relays. Encrypted files are automatically decrypted.

```bash
nostrsave download <MANIFEST> [OPTIONS]
nostrsave download --hash <HASH> [OPTIONS]

Options:
  --hash <HASH>        File hash to fetch from relays
  -o, --output <PATH>  Output file path
  --stats              Show relay statistics
  -v, --verbose        Verbose output
```

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
nostrsave discover-relays [OPTIONS]

Options:
  -o, --output <PATH>     Output JSON file (default: relays.json)
  --configured-only       Only test configured relays
  --timeout <SECONDS>     Connection timeout (default: 10)
  --concurrent <N>        Max concurrent tests (default: 20)
  --chunk-size <BYTES>    Payload size for round-trip test
```

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
nostrsave discover-relays
nostrsave best-relays -c 10
# Copy output to config.toml [relays] section
```

## How It Works

Files are split into chunks (default 65408 bytes, NIP-44 max), encrypted with NIP-44 (self-encryption), and published as Nostr events. A manifest event ties all chunks together. An optional file index event tracks all your uploads.

**Encryption:** By default, chunks are encrypted using NIP-44 with your own public key. Only you can decrypt them with your private key. Use `--no-encrypt` to upload unencrypted files.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for technical details.

## Event Kinds

| Kind  | Description |
|-------|-------------|
| 30078 | File chunk (parameterized replaceable) |
| 30079 | File manifest |
| 30080 | File index |

## License

MIT
