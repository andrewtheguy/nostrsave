# Roadmap

## Ideas

### AES-256-GCM Chunk Encryption (see also: Passkey PRF Extension)
Encrypt each chunk individually with AES-256-GCM before publishing:
- Decouple encryption from Nostr identity - use separate encryption keys
- Key derivation options: passphrase, PRF-derived, or recipient public key
- Chunks published as "unencrypted" events (no NIP-44 wrapper), reducing overhead
- Manifest stores key derivation parameters
- Enables sharing encrypted files by encrypting to recipient's public key

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

### Relay Discovery Cache
Cache discovered relay test results in a persistent SQLite database for faster relay selection and usage tracking:
- Store relay URLs with test results (latency, can_write, can_read, round_trip_ms)
- Include timestamps for cache expiration (e.g., 24-hour TTL)
- Store in `~/.config/nostrsave/relay_cache.db`
- Skip re-testing recently validated relays during `discover-relays`
- Provide `--force-refresh` flag to ignore cache
- Track relay usage counts and last-used timestamps for rotation
- Enable smarter relay selection based on historical performance
- Could track success/failure rates over time for reliability scoring

### Rotating Data Relay Mode (depends on Relay Discovery Cache)
Configure a large pool of data relays and rotate through them during uploads:
- Config specifies a pool of candidate relays
- Each upload session selects a subset of relays from the pool
- Optionally rotate relays within a session (different chunks to different relays)
- Manifest records which relays received which chunks
- Spreads storage load across many relays
- Reduces dependency on any single relay's availability
- Avoids rate limits by distributing requests across relays

### Space-Efficient Download Mode
Reduce disk usage during download by purging chunks from the session database as they are written to the output file:
- Wait until all chunks are downloaded to the session DB
- During assembly, delete each chunk from the DB after writing it to the output file
- Avoids having both the full DB and the assembled file on disk simultaneously
- Useful for large files where disk space is limited
- Trade-off: cannot resume assembly if interrupted mid-assembly (would need to re-download)

### Delete Entry from Index
Remove a file entry from the index:
- `nostrsave delete <hash>` removes entry from index
- If entry is on current index (page 1): republish with entry removed
- If entry is on an archive page: fetch, remove entry, republish that archive
- Only the affected page is republished; other pages unchanged
- Uploaded chunks and manifest remain on relays (no way to force relay deletion)
- Useful for cleaning up index after failed uploads or unwanted entries

### Passkey PRF Extension for Key Derivation (see also: AES-256-GCM Chunk Encryption)
Use WebAuthn PRF (Pseudo-Random Function) extension for hardware-backed key derivation:
- FIDO2 authenticators (YubiKey, Touch ID, etc.) provide secure key derivation
- Deterministic: same passkey + salt always produces same key material
- Two use cases:
  1. Derive Nostr keypair - no private key stored on disk
  2. Derive encryption key only - protects file content even if nsec is stolen
- Self-transfer scenario: use existing nsec for publishing, PRF for encryption
  - Attacker with stolen nsec can see events but cannot decrypt file contents
- Could integrate with web interface for browser-based key derivation
- Requires PRF-compatible authenticator and browser support

