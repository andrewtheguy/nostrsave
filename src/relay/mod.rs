mod discovery;

pub use discovery::{
    discover_relays_from_index, discover_relays_from_nostr_watch, test_relays_concurrent,
    RelayTestResult,
};
