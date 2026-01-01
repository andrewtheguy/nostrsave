# Architecture

## Project Structure

```
src/
├── main.rs              # Entry point, CLI argument handling
├── cli.rs               # Clap command definitions
├── config.rs            # TOML config, relay loading, constants
├── crypto.rs            # NIP-44 encryption/decryption
├── error.rs             # Error types
├── manifest.rs          # Manifest structure and serialization
├── commands/
│   ├── mod.rs
│   ├── upload.rs        # Upload command implementation
│   ├── download.rs      # Download command implementation
│   ├── list.rs          # List command implementation
│   ├── discover_relays.rs  # Relay discovery command
│   └── best_relays.rs   # Best relays command
├── chunking/
│   ├── mod.rs
│   ├── splitter.rs      # File chunking logic
│   └── assembler.rs     # Chunk reassembly logic
├── nostr/
│   ├── mod.rs
│   ├── events.rs        # Event creation and parsing
│   └── index.rs         # File index event handling
└── relay/
    ├── mod.rs
    └── discovery.rs     # Relay discovery and testing
```

## Data Flow

### Upload Flow

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│  Read File  │────▶│ Split Chunks │────▶│ Encrypt (NIP-44)│
└─────────────┘     └──────────────┘     └─────────────────┘
                                                  │
                                                  ▼
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│ Save Local  │◀────│ Publish      │◀────│ Sign & Publish  │
│ Manifest    │     │ Manifest     │     │ Chunk Events    │
└─────────────┘     └──────────────┘     └─────────────────┘
                           │
                           ▼
                    ┌──────────────┐
                    │ Update File  │
                    │ Index        │
                    └──────────────┘
```

### Download Flow

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│ Load/Fetch  │────▶│ Query Relays │────▶│ Collect Chunks  │
│ Manifest    │     │ for Chunks   │     │                 │
└─────────────┘     └──────────────┘     └─────────────────┘
                                                  │
                                                  ▼
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│ Write File  │◀────│ Verify Hash  │◀────│ Decrypt (NIP-44)│
│             │     │              │     │ & Reassemble    │
└─────────────┘     └──────────────┘     └─────────────────┘
```

## Nostr Event Structure

### Chunk Event (Kind 30078)

Parameterized replaceable event storing one file chunk.

```
Kind: 30078
Content: <NIP-44 encrypted or base64-encoded chunk data>
Tags:
  - ["d", "<file_hash>:<chunk_index>"]     # Unique identifier
  - ["x", "<file_hash>"]                   # File hash for filtering
  - ["chunk", "<index>", "<total>"]        # Position info
  - ["hash", "<chunk_hash>"]               # Chunk integrity
  - ["filename", "<name>"]                 # Original filename
  - ["size", "<bytes>"]                    # Chunk size
  - ["encryption", "nip44|none"]            # Encryption algorithm
```

### Manifest Event (Kind 30079)

Parameterized replaceable event containing file metadata.

```
Kind: 30079
Content: <JSON manifest>
Tags:
  - ["d", "<file_hash>"]                   # Unique identifier
  - ["x", "<file_hash>"]                   # For filtering
  - ["filename", "<name>"]                 # Original filename
  - ["size", "<total_bytes>"]              # Total file size
```

**Manifest JSON:**
```json
{
  "version": 1,
  "file_name": "photo.jpg",
  "file_hash": "sha256:abc123...",
  "file_size": 1234567,
  "chunk_size": 32768,
  "total_chunks": 19,
  "created_at": 1704067200,
  "pubkey": "npub1...",
  "encryption": "nip44",
  "chunks": [
    {"index": 0, "event_id": "note1...", "hash": "sha256:..."},
    ...
  ],
  "relays": ["wss://relay.damus.io", ...]
}
```

### File Index Event (Kind 30080)

Parameterized replaceable event listing all user's files.

```
Kind: 30080
Content: <JSON file index>
Tags:
  - ["d", "nostrsave-index"]               # Fixed identifier
```

**Index JSON:**
```json
{
  "version": 1,
  "entries": [
    {
      "file_hash": "sha256:abc123...",
      "file_name": "photo.jpg",
      "file_size": 1234567,
      "uploaded_at": 1704067200,
      "encryption": "nip44"
    },
    ...
  ]
}
```

## Configuration Loading

```
┌─────────────────────────────────────────────────────────┐
│                    Priority Order                        │
├─────────────────────────────────────────────────────────┤
│ 1. CLI flags (--key-file, --encryption)                 │
│    ↓                                                     │
│ 2. TOML config (~/.config/nostrsave/config.toml)        │
│    - [identity] private_key or key_file                 │
│    - [data_relays] for chunk storage                    │
│    - [index_relays] for manifest/index discovery        │
│    - [encryption] algorithm (nip44 or none)             │
│    ↓                                                     │
│ 3. Built-in defaults (nip44, fallback relays)           │
└─────────────────────────────────────────────────────────┘
```

## Chunking Strategy

- **Default chunk size:** 32 KB (32768 bytes)
- **Maximum:** 65408 bytes (tested limit for reliable relay storage)
- **Range:** 1 KB to 65408 bytes (tested max)
- **Hash algorithm:** SHA-256 (computed on original, unencrypted data)
- **Encoding:** NIP-44 encrypted (default) or base64

### Why Chunking?

1. **Relay limits:** Most relays have event size limits
2. **NIP-44 limits:** Protocol allows up to 65535 bytes, but 65408 is the tested limit that works reliably with relays
3. **Parallel fetching:** Chunks can be fetched concurrently
4. **Resumability:** Failed uploads/downloads can resume
5. **Deduplication:** Identical chunks share the same hash

## Encryption (NIP-44)

Files are encrypted by default using NIP-44 self-encryption:

1. **Self-encryption:** Chunks are encrypted using your secret key + your public key
2. **Only you can decrypt:** Only the owner (matching private key) can decrypt the file
3. **Hash integrity:** File and chunk hashes are computed on original (unencrypted) data
4. **Per-chunk encryption:** Each chunk is encrypted independently
5. **Opt-out available:** Use `--encryption none` to upload unencrypted files

## Relay Discovery

The `discover-relays` command tests relays for file storage capability.

### Relay Sources

1. **nostr.watch API** (`https://api.nostr.watch/v1/online`)
   - Returns list of currently online relays
   - Skipped if `--configured-only` flag is used

2. **Index relays** (from config or built-in defaults)
   - Always included in discovery
   - Typically more reliable for file index storage

### Reliability Criteria

A relay is considered "working" only if ALL conditions pass:

| Criterion | Description |
|-----------|-------------|
| `connected` | WebSocket connection established within timeout |
| `can_write` | Successfully published a test event with NIP-44 encrypted payload |
| `can_read` | Successfully fetched the test event back and verified decryption matches |

The test uses the same event kind (30078) and encryption (NIP-44) as actual file uploads.

### Output Fields

```json
{
  "working_relays": [
    {
      "url": "wss://relay.example.com",
      "connected": true,
      "latency_ms": 150,
      "can_write": true,
      "can_read": true,
      "round_trip_ms": 520,
      "payload_size": 32768
    }
  ],
  "failed_relays": [
    {
      "url": "wss://slow.relay.io",
      "connected": true,
      "latency_ms": 200,
      "can_write": true,
      "can_read": false,
      "round_trip_ms": 8500,
      "payload_size": 32768,
      "error": "Event not found on read"
    }
  ]
}
```

| Field | Description |
|-------|-------------|
| `url` | Relay WebSocket URL |
| `connected` | TCP/WebSocket connection succeeded |
| `latency_ms` | Time to establish connection |
| `can_write` | Event publish succeeded |
| `can_read` | Event fetch and decryption succeeded |
| `round_trip_ms` | Full write→read cycle time |
| `payload_size` | Test payload size (matches `--chunk-size`) |
| `error` | Error message if any test failed |

### Usage with best-relays

The output can be fed to `best-relays` to extract the fastest working relays:

```bash
nostrsave discover-relays -o relays.json
nostrsave best-relays relays.json --count 5
```

## Security Considerations

- **NIP-44 encryption:** File chunks are encrypted by default
- **Self-encryption only:** Only the file owner can decrypt (private key required)
- **Key verification:** Download verifies user's pubkey matches manifest before decryption
- Private keys are never stored in manifests
- Key files support tilde expansion for home directory
- Config file can reference external key files
- Chunk hashes verified on download (against original unencrypted data)
- File hash verified after reassembly

## Dependencies

| Crate | Purpose |
|-------|---------|
| nostr-sdk | Nostr protocol implementation (with nip44 feature) |
| clap | CLI argument parsing |
| tokio | Async runtime |
| serde/serde_json | JSON serialization |
| toml | TOML config parsing |
| sha2 | SHA-256 hashing |
| base64 | Binary encoding |
| indicatif | Progress bars |
| reqwest | HTTP client for relay discovery |
| dirs | Platform config directories |
| chacha20 | NIP-44 encryption (via nostr-sdk) |
