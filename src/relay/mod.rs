mod discovery;

pub use discovery::{
    discover_relays_from_index, discover_relays_from_nostr_watch, fetch_user_write_relays,
    test_relays_concurrent, RelayTestResult,
};
