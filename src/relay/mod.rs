mod discovery;

pub use discovery::{
    discover_relays_from_nip65, discover_relays_from_nostr_watch, test_relays_concurrent,
    RelayTestResult,
};
