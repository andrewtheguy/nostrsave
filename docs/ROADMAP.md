# Roadmap

## Ideas

### Encrypted File Sharing
Enable sharing encrypted files with specific recipients:
- Encrypt file key using recipient's public key (NIP-44 or similar)
- Store encrypted key parameters in the manifest
- Allows secure sharing without revealing the uploader's private key
- Receiver derives/decrypts the file key to decrypt chunks

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
Implemented (current): `discover-relays` persists the working relay list to `data_relays.sqlite3` in the config directory and tracks `last_used_at` + a rolling cursor for upload rotation.

Future expansion ideas:
- Store test metrics (latency/can_write/can_read/round_trip_ms) and success/failure history
- Add cache expiration / TTL and `--force-refresh`
- Skip re-testing recently validated relays during `discover-relays`

### Rotating Data Relay Mode (depends on Relay Discovery Cache)
Implemented (current): set `[data_relays].source = "discovered"` and `[data_relays].batch_size` to rotate through the discovered relay pool across uploads (1–N, then N+1–2N, etc.).

Future expansion ideas:
- Rotate within a single upload session (different chunks to different relays)
- Record per-chunk relay placement in the manifest

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

### Passkey PRF Extension for Key Derivation (see also: Encrypted File Sharing)
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

### Hierarchical Index Mode (Folder Support)
Evolve the flat file index into a hierarchical structure using folder entries:
- Index events store folder metadata instead of just a flat list of files
- Folders are represented as nested objects or separate sub-index events
- Root directory remains anchored to the user's npub
- Enables organized file management (add/remove/rename) within a folder-based UI
- Maintains compatibility with the existing index-based discovery mechanism
