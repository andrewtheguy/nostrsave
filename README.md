# nostrsave

A CLI tool for storing and retrieving files on the Nostr network.

## Features

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

# Upload a file
nostrsave upload photo.jpg -k nsec1...

# List your indexed files
nostrsave list -k nsec1...

# Download a file by hash
nostrsave download --hash sha256:abc123...
```

## Configuration

Create `~/.config/nostrsave/config.toml`:

```toml
[identity]
# Option 1: Inline key
private_key = "nsec1..."

# Option 2: Key file path (supports ~)
key_file = "~/.config/nostrsave/nostr.key"

[relays]
urls = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://nostr.wine",
]
```

### Priority Order

1. CLI flags (`-k`, `--key-file`, `-r`)
2. TOML config (`config.toml`)
3. Legacy file (`relays.txt`)
4. Environment variable (`NOSTRSAVE_RELAYS`)
5. Built-in fallback relays

## Commands

### upload

Upload a file to Nostr relays.

```bash
nostrsave upload <FILE> [OPTIONS]

Options:
  -c, --chunk-size <BYTES>  Chunk size (1KB-1MB, default: 64KB)
  -o, --output <PATH>       Output manifest file path
  -k <KEY>                  Private key (hex or nsec)
  --key-file <PATH>         Path to key file
  -r, --relay <URL>         Relay URLs (repeatable)
  -v, --verbose             Verbose output
```

### download

Download a file from Nostr relays.

```bash
nostrsave download <MANIFEST> [OPTIONS]
nostrsave download --hash <HASH> [OPTIONS]

Options:
  --hash <HASH>      File hash to fetch from relays
  -o, --output <PATH>  Output file path
  --stats            Show relay statistics
```

### list

List files in your Nostr file index.

```bash
nostrsave list [OPTIONS]

Options:
  --pubkey <NPUB>    List files for another user
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

## How It Works

Files are split into chunks (default 64KB), each published as a Nostr event. A manifest event ties all chunks together. An optional file index event tracks all your uploads.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for technical details.

## Event Kinds

| Kind  | Description |
|-------|-------------|
| 30078 | File chunk (parameterized replaceable) |
| 30079 | File manifest |
| 30080 | File index |

## License

MIT
