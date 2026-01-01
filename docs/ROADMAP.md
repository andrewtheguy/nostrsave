# Roadmap

## Planned Features

### Resumable Upload
- Track upload progress in a local state file
- On interruption, resume from the last successfully published chunk
- Skip chunks that already exist on relays (by event ID or hash)

### Resumable Download
- Track download progress in a local state file
- On interruption, resume fetching missing chunks
- Assemble partial files only when all chunks are available

## Ideas

### AES-256-GCM Chunk Encryption
Encrypt each chunk individually with AES-256-GCM before publishing. The encryption key would be derived from the user's Nostr key or a separate passphrase. Chunks would be published as "unencrypted" events (no NIP-44 wrapper), reducing overhead while maintaining confidentiality. The manifest would store the key derivation parameters.

### Relay Publishing Server
An intermediate server that accepts chunk submissions and handles relay publishing:
- Client uploads chunk to server once
- Server publishes to multiple relays in parallel
- Reduces client bandwidth and connection overhead
- Could batch multiple users' events for efficiency

### Event Persistence Server
A server that periodically republishes events to keep them live:
- Monitor relay retention policies
- Republish events before they expire
- Ensure long-term data availability
- Could run as a paid service or self-hosted

### Web Download Interface
A web page for downloading files without the CLI:
- Enter file hash or scan QR code
- Fetch manifest and chunks via WebSocket
- Decrypt in browser (if encrypted)
- Download assembled file
- Could be hosted on IPFS or as a static site

### Rotating Data Relay Mode
Configure a large pool of data relays and rotate through them during uploads:
- Config specifies a pool of candidate relays
- Each upload session selects a subset of relays from the pool
- Optionally rotate relays within a session (different chunks to different relays)
- Manifest records which relays received which chunks
- Spreads storage load across many relays
- Reduces dependency on any single relay's availability
- Avoids rate limits by distributing requests across relays

