/// Default relays for uploading and downloading
pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.nostr.band",
    "wss://nostr.wine",
    "wss://relay.nostr.bg",
];

/// Custom event kind for file chunks (parameterized replaceable)
pub const CHUNK_EVENT_KIND: u16 = 30078;
