# Architecture

## Project Structure

```
src/
├── main.rs              # Entry point, CLI argument handling
├── cli.rs               # Clap command definitions
├── config.rs            # TOML config, relay loading, constants
├── error.rs             # Error types
├── manifest.rs          # Manifest structure and serialization
├── commands/
│   ├── mod.rs
│   ├── upload.rs        # Upload command implementation
│   ├── download.rs      # Download command implementation
│   ├── list.rs          # List command implementation
│   └── discover_relays.rs  # Relay discovery command
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
│  Read File  │────▶│ Split Chunks │────▶│ Create Events   │
└─────────────┘     └──────────────┘     └─────────────────┘
                                                  │
                                                  ▼
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│ Save Local  │◀────│ Publish      │◀────│ Sign Events     │
│ Manifest    │     │ Manifest     │     │ (Chunks)        │
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
│ Write File  │◀────│ Verify Hash  │◀────│ Reassemble      │
└─────────────┘     └──────────────┘     └─────────────────┘
```

## Nostr Event Structure

### Chunk Event (Kind 30078)

Parameterized replaceable event storing one file chunk.

```
Kind: 30078
Content: <base64-encoded chunk data>
Tags:
  - ["d", "<file_hash>:<chunk_index>"]     # Unique identifier
  - ["x", "<file_hash>"]                   # File hash for filtering
  - ["chunk", "<index>", "<total>"]        # Position info
  - ["hash", "<chunk_hash>"]               # Chunk integrity
  - ["filename", "<name>"]                 # Original filename
  - ["size", "<bytes>"]                    # Chunk size
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
  "chunk_size": 65536,
  "total_chunks": 19,
  "created_at": 1704067200,
  "pubkey": "npub1...",
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
      "uploaded_at": 1704067200
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
│ 1. CLI flags (-k, --key-file, -r)                       │
│    ↓                                                     │
│ 2. TOML config (~/.config/nostrsave/config.toml)        │
│    ↓                                                     │
│ 3. Legacy file (~/.config/nostrsave/relays.txt)         │
│    ↓                                                     │
│ 4. Environment (NOSTRSAVE_RELAYS)                       │
│    ↓                                                     │
│ 5. Fallback defaults                                     │
└─────────────────────────────────────────────────────────┘
```

## Chunking Strategy

- **Default chunk size:** 64 KB
- **Range:** 1 KB to 1 MB
- **Hash algorithm:** SHA-256
- **Encoding:** Base64 for event content

### Why Chunking?

1. **Relay limits:** Most relays have event size limits
2. **Parallel fetching:** Chunks can be fetched concurrently
3. **Resumability:** Failed uploads/downloads can resume
4. **Deduplication:** Identical chunks share the same hash

## Relay Discovery

The `discover-relays` command:

1. Fetches public relay lists from known sources
2. Tests connectivity to each relay
3. Performs round-trip test with actual payload size
4. Outputs JSON with timing and success metrics

## Security Considerations

- Private keys are never stored in manifests
- Key files support tilde expansion for home directory
- Config file can reference external key files
- Chunk hashes verified on download
- File hash verified after reassembly

## Dependencies

| Crate | Purpose |
|-------|---------|
| nostr-sdk | Nostr protocol implementation |
| clap | CLI argument parsing |
| tokio | Async runtime |
| serde/serde_json | JSON serialization |
| toml | TOML config parsing |
| sha2 | SHA-256 hashing |
| base64 | Binary encoding |
| indicatif | Progress bars |
| reqwest | HTTP client for relay discovery |
| dirs | Platform config directories |
